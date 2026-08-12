# CH-J Server Manager Core

Nová implementace CH-J Server Manager. Uživatelský název aplikace zůstává beze změny; „Core“ označuje pouze novou architekturu.

## Aktuální implementační řez

- bezpečný Electron bootstrap;
- jediný omezený preload bridge;
- atomická necitlivá konfigurace;
- plugin manifest a registr nainstalovaných pluginů;
- `HashUrlProvider` pro PHP kanály `alpha`, `beta` a `stable`, včetně složeného pohledu `all`;
- kontrola platformy, architektury, verze, velikosti a SHA-512;
- stažení do interního stagingu bez automatického spuštění;
- šifrovaný vault (scrypt + AES-256-GCM) s ručním zamknutím;
- vytváření a úpravy serverových profilů;
- volitelné SSH heslo uložené odděleně v šifrované části vaultu a automaticky použité při prázdném přihlašovacím poli;
- více-relacový SSH `SessionManager` s password/private-key autentizací;
- předběžné DNS rozlišení SSH hostname, přesná chyba při chybějícím záznamu a preference IPv4 při současném A/AAAA záznamu;
- povinná kontrola SHA-256 SSH host key, potvrzení prvního klíče a explicitní potvrzení ověřené náhrady změněného klíče;
- interaktivní terminál s inputem a změnou velikosti;
- omezený SFTP transport v Core s absolutními cestami, editorem do 25 MiB, multi-upload/download přenosy do 16 GiB a exportem ZIP/TAR/TAR.GZ;
- i18n runtime s kompletními katalogy pro češtinu, němčinu a angličtinu;
- webový katalog, SHA-512 instalace, sandboxované spouštění a odinstalování `.chjplugin` balíčků;
- pluginy System Monitor (včetně CPU/RAM/swap/disk/síťových metrik), Key Generator, Log Viewer, Users, File Manager a NGINX Manager jako samostatné instalovatelné balíčky;
- shell UI a automatické testy.

Zatím chybí migrace dat starších verzí, SFTP přenosová fronta/resume/sudo save a vzdálené rozbalování archivů, jump host/forwarding, Safe Mode a další plánované Tools. Ověřený instalátor Core lze předat platformě ručně; plně bezobslužná instalace zatím není povolená. SSH heslo lze volitelně uložit ve vaultu; passphrase soukromého klíče se neukládá a zadává se pro konkrétní připojení. Platformní a release stav je vedený v `../PROJECT-STATUS.md`.

## Vývoj

```bash
npm install
npm test
npm start
```

Při prvním startu aplikace vyžádá vytvoření hlavního hesla vaultu o délce 4 až 64 znaků. Potom vytvořte profil v části **Servery** a připojte se v části **Terminál**. Otisk prvního host klíče vždy ověřte také jiným důvěryhodným kanálem.

Pokud se známý SSH host klíč změní, Core připojení nejprve zablokuje a zobrazí původní i nový SHA-256 fingerprint. Nový fingerprint lze uložit pouze samostatným varovným potvrzením obou hodnot; potvrzení použijte až po jejich ověření jiným důvěryhodným kanálem.

Na zamykací obrazovce lze použít **Zapomenuté heslo / obnovit vault**. Protože bez původního hesla nelze data dešifrovat, obnova odstraní serverové profily, důvěryhodné host fingerprinty a ostatní šifrovaná data. Nastavení aktualizací a instalované pluginy nemaže.

Jazyk lze změnit přímo na zamykací obrazovce nebo v části **Nastavení**. Volba `cs`, `de` nebo `en` se ukládá do necitlivé lokální konfigurace a použije se při dalším startu.

Alpha updater používá pouze HTTPS endpoint `https://sm.ch-j.de/` definovaný v main procesu. Veřejný server již má platný Let’s Encrypt certifikát, Core však v dočasném testovacím režimu stále přijímá libovolný certifikát tohoto jediného pevně povoleného hostitele. HTTPS a allowlist zůstávají povinné, ale standardní ověření CA je nutné co nejdříve znovu zapnout. SHA-512 ověřuje přesný obsah artefaktu, nikoli identitu vydavatele.

Kanály mají v aplikaci i PHP serveru shodné názvy `alpha`, `beta`, `stable`; historické `dev` není alias a je odmítnuto. Aktualizace Core a katalog pluginů mají samostatně uloženou volbu kanálu. Volba `all`/„Vše“ je pouze klientský pohled, který bezpečně načte a sloučí všechny tři skutečné kanály. macOS distribuce a aktualizace se vytvářejí pouze pro Apple Silicon (`arm64`), nikoli pro Intel (`x64`).

`npm run dist:mac` vytváří dva oddělené artefakty: DMG pro automatickou aktualizaci a `*.app.zip` pro první instalaci z webu. ZIP zachovává strukturu macOS bundle a build krok ověřuje `codesign` před i po zabalení. Bez certifikátu Developer ID Application vznikne jen ad-hoc podepsaný testovací build, který může být nutné ručně povolit v nastavení Soukromí a zabezpečení. Pro bezobslužnou webovou instalaci musí být `.app` podepsaná Developer ID, používat hardened runtime a být notarizována Applem.

Obrazovka aktualizací načítá celý kompatibilní katalog pro aktuální platformu, architekturu a kanál. Každý release rozlišuje pomocí serverového `id` a `published_at`, takže lze ručně vybrat, stáhnout, ověřit a spustit také jiný build se stejným číslem verze. Spuštění instalátoru je vždy ruční a dostupné až po úspěšné kontrole SHA-512.

Správce pluginů načítá katalog pouze z povoleného originu `https://sm.ch-j.de/`; HTTP, přímé IP adresy a staré QNAP adresy Core nepovoluje. V alfa režimu je ověření CA dočasně vypnuté jen pro tento origin. Nesouhlas velikosti nebo SHA-512 je bezpečnostní chyba a balíček se nepoužije. Samostatné balíčky `.chjplugin` bezpečně rozbaluje do stagingu a atomicky instaluje do uživatelského adresáře. Nainstalovaný plugin lze odstranit; před smazáním všech jeho nainstalovaných verzí Core zavře jeho okno. Vault ani konfigurace Core se tím nemažou. Pluginová okna mají vlastní sandbox, pevný preload a capability odvozené z ověřeného manifestu. Aktuální Plugin API je `1.1.0`; katalog dostává tuto verzi v parametru `plugin_api` a nekompatibilní vydání odfiltruje. V alfa katalogu jsou publikované pluginy `chj.system-monitor`, `chj.key-generator`, `chj.log-viewer`, `chj.users`, `chj.file-manager` a `chj.nginx-manager`.

NGINX Manager používá jen `session.read`, `nginx.read` a `nginx.manage`. Umí inventář a omezené čtení konfigurace, `nginx -T`, editaci souborů do 512 KiB s časovanou zálohou, `nginx -t`, automatický rollback a potvrzený graceful reload. Vyžaduje Plugin API `^1.1.0`; starší Core jej proto v katalogu neuvidí.

File Manager používá existující ověřenou SSH relaci, ale místo obecného vzdáleného shellu dostává jen capability `files.read`, `files.write` a `files.transfer`. Nabízí interaktivní vícenásobný výběr, řazení, filtrování, breadcrumbs, kontextové menu, klávesové zkratky a přibalený offline Monaco Editor s limitem 25 MiB. Core zajišťuje atomický zápis, multi-upload souborů/složek, rekurzivní hromadný download, potvrzované rekurzivní mazání a export výběru jako ZIP, TAR nebo TAR.GZ. Protože alfa buildy zatím sdílejí verzi `0.0.1`, plugin na starším Core bez rozšířeného `files.*` zobrazí požadavek na aktualizaci aplikace a své ovládání bezpečně deaktivuje. Sudo save, vzdálené rozbalování archivů, fronta přenosů a resume zatím nejsou implementované.

Nainstalovaný plugin se neporovnává jen podle verze manifestu. Registry uchovává také serverové release ID a SHA-512, takže lze nabídnout a atomicky přeinstalovat novější alfa build se stejnou verzí, například aktualizovaný `chj.key-generator` 0.0.1.

SSH profil může používat IP adresu i DNS hostname. Core nejprve zkusí systémový resolver a při jeho chybě provede přímé DNS dotazy A/AAAA; `ssh2` potom dostane již vybranou číselnou adresu. Pokud jsou dostupné oba typy záznamu, pro současnou konfiguraci preferuje IPv4. Host-key databáze, UI i auditní log nadále používají původní DNS jméno, takže překlad neoslabuje kontrolu identity serveru. Teprve DNS jméno bez použitelného záznamu vrátí `SSH_DNS_RESOLUTION_FAILED`.
