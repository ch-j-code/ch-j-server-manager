#!/usr/bin/python3
"""Private one-request helper: fprintd on system D-Bus + libsecret on session D-Bus.
No PAM changes, root access, plaintext key files or Electron basic_text backend.
"""
import json,sys,signal,base64
class Failure(Exception): pass
def failure(code): raise Failure(code)
def main():
    request=json.loads(sys.stdin.buffer.read(4097))
    try:
        import gi
        gi.require_version('Secret','1')
        from gi.repository import Gio,GLib,Secret
    except (ImportError,ValueError): failure('BIOMETRIC_KEYRING_UNAVAILABLE')
    op=request.get('op');entry=request.get('entryId');reason=str(request.get('reason','CH-J Server Manager'))[:200]
    schema=Secret.Schema.new('de.ch-j.servermanager.vault.biometry.v1',Secret.SchemaFlags.NONE,{'vault':Secret.SchemaAttributeType.STRING})
    def keyring():
        try:
            service=Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION | Secret.ServiceFlags.LOAD_COLLECTIONS,None)
            if service is None: failure('BIOMETRIC_KEYRING_UNAVAILABLE')
            # Only the explicit Secret Service API is used; there is no fallback backend.
            collection=Secret.Collection.for_alias_sync(service,Secret.COLLECTION_DEFAULT,Secret.CollectionFlags.NONE,None)
            if collection is None: failure('BIOMETRIC_KEYRING_UNAVAILABLE')
            return service
        except GLib.Error: failure('BIOMETRIC_KEYRING_UNAVAILABLE')
    def device():
        try:
            manager=Gio.DBusProxy.new_for_bus_sync(Gio.BusType.SYSTEM,Gio.DBusProxyFlags.NONE,None,'net.reactivated.Fprint','/net/reactivated/Fprint/Manager','net.reactivated.Fprint.Manager',None)
            path=manager.call_sync('GetDefaultDevice',None,Gio.DBusCallFlags.NONE,5000,None).unpack()[0]
            proxy=Gio.DBusProxy.new_for_bus_sync(Gio.BusType.SYSTEM,Gio.DBusProxyFlags.NONE,None,'net.reactivated.Fprint',path,'net.reactivated.Fprint.Device',None)
            fingers=proxy.call_sync('ListEnrolledFingers',GLib.Variant('(s)',('',)),Gio.DBusCallFlags.NONE,5000,None).unpack()[0]
            if not fingers: failure('BIOMETRIC_NO_ENROLLMENT')
            return proxy
        except GLib.Error as e:
            if 'NoEnrolledPrints' in str(e): failure('BIOMETRIC_NO_ENROLLMENT')
            failure('BIOMETRIC_UNAVAILABLE')
    def authenticate():
        proxy=device();loop=GLib.MainLoop();state={'code':'BIOMETRIC_FAILED','claimed':False,'started':False,'timeout':None}
        def call(method,args=None):return proxy.call_sync(method,args,Gio.DBusCallFlags.NONE,5000,None)
        def on_signal(_proxy,_sender,name,params):
            if name!='VerifyStatus':return
            result,done=params.unpack()
            if result=='verify-match':state['code']=None;loop.quit()
            elif result=='verify-no-match':state['code']='BIOMETRIC_FAILED';loop.quit()
            elif result=='verify-disconnected':state['code']='BIOMETRIC_DEVICE_UNAVAILABLE';loop.quit()
            elif done:loop.quit()
        def stop(code):state['code']=code;loop.quit();return False
        handler=proxy.connect('g-signal',on_signal)
        old_handlers={}
        try:
            call('Claim',GLib.Variant('(s)',('',)));state['claimed']=True
            for sig in [signal.SIGTERM,signal.SIGINT]:old_handlers[sig]=signal.signal(sig,lambda _s,_f:stop('BIOMETRIC_CANCELLED'))
            state['timeout']=GLib.timeout_add_seconds(60,lambda:stop('BIOMETRIC_TIMEOUT'))
            call('VerifyStart',GLib.Variant('(s)',('any',)));state['started']=True
            loop.run()
            if state['code']:failure(state['code'])
        except GLib.Error:failure('BIOMETRIC_DEVICE_UNAVAILABLE')
        finally:
            if state['timeout']:
                try:GLib.source_remove(state['timeout'])
                except Exception:pass
            if state['started']:
                try:call('VerifyStop')
                except Exception:pass
            if state['claimed']:
                try:call('Release')
                except Exception:pass
            proxy.disconnect(handler)
            for sig,handler in old_handlers.items():signal.signal(sig,handler)
    if op=='status':
        try:keyring();device();return {'ok':True,'available':True,'code':'BIOMETRIC_AVAILABLE'}
        except Failure as e:return {'ok':True,'available':False,'code':str(e)}
    if op=='authenticate':authenticate();return {'ok':True}
    if not isinstance(entry,str) or len(entry)!=64 or any(c not in '0123456789abcdef' for c in entry):failure('BIOMETRIC_FAILED')
    keyring();attrs={'vault':entry}
    try:
        if op=='store':
            encoded=request.get('key','');key=bytearray(base64.b64decode(encoded,validate=True))
            if len(key)!=32:failure('BIOMETRIC_INVALID_KEY')
            try:
                if not Secret.password_store_sync(schema,attrs,Secret.COLLECTION_DEFAULT,'CH-J Server Manager Vault',encoded,None):failure('BIOMETRIC_CREDENTIAL_FAILED')
            finally:key[:]=b'\0'*len(key)
            return {'ok':True}
        if op=='remove':Secret.password_clear_sync(schema,attrs,None);return {'ok':True}
        if op=='retrieve':
            authenticate()
            value=Secret.password_lookup_sync(schema,attrs,None)
            if value is None:failure('BIOMETRIC_ENROLLMENT_INVALIDATED')
            if len(base64.b64decode(value,validate=True))!=32:failure('BIOMETRIC_INVALID_KEY')
            return {'ok':True,'key':value}
    except GLib.Error:failure('BIOMETRIC_CREDENTIAL_FAILED')
    failure('BIOMETRIC_FAILED')
try:
    result=main();print(json.dumps(result));sys.exit(0)
except Failure as e:print(json.dumps({'ok':False,'code':str(e)}));sys.exit(1)
except Exception:print(json.dumps({'ok':False,'code':'BIOMETRIC_FAILED'}));sys.exit(1)
