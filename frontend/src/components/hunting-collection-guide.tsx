import { useId, useState } from "react"
import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { FileDown } from "lucide-react"

const windowsRun = String.raw`# PowerShell от администратора. Сначала распакуйте ZIP в C:\BroSec\package.
$ErrorActionPreference = 'Stop'
$package = 'C:\BroSec\package'
$manifest = Get-Content "$package\manifest.json" -Raw | ConvertFrom-Json
$binary = "$package\BroSec-Collector.exe"
if ((Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.executable_sha256) {
    throw 'SHA256 не совпадает; запуск запрещён'
}
$run = Join-Path 'C:\ProgramData\BroSec\Evidence' ($env:COMPUTERNAME + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $run -ErrorAction Stop | Out-Null
& icacls.exe $run /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Не удалось ограничить ACL' }
Push-Location $run
try {
    & $binary *> .\collector.log
    if ($LASTEXITCODE -ne 0) { throw 'Сборщик завершился с ошибкой; проверьте защищённый журнал' }
    $results = @(Get-ChildItem -File -Filter 'BroSec-*.zip')
    if ($results.Count -ne 1) { throw 'Ожидался один ZIP; проверьте результат' }
    $results | Get-FileHash -Algorithm SHA256
} finally { Pop-Location }`

const linuxRun = String.raw`# Распакованный пакет: /opt/brosec/package; каталог не доступен на запись обычным пользователям.
# Выполняйте из одобренной административной сессии; проверка SHA256 — до sudo-запуска.
set -eu
cd /opt/brosec/package
python3 - <<'PY'
import hashlib, json
from pathlib import Path
p = Path('BroSec-Collector')
expected = json.loads(Path('manifest.json').read_text())['executable_sha256']
if hashlib.sha256(p.read_bytes()).hexdigest() != expected:
    raise SystemExit('SHA256 mismatch: STOP')
PY
# Продолжать только если проверка выше успешна.
sudo chown -R root:root /opt/brosec/package
sudo chmod 0700 /opt/brosec/package /opt/brosec/package/BroSec-Collector
sudo bash <<'SH'
set -eu
umask 077
run="/var/lib/brosec/$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p /var/lib/brosec
chmod 0700 /var/lib/brosec
mkdir -m 0700 "$run"
cd "$run"
/opt/brosec/package/BroSec-Collector >collector.log 2>&1
# Архив остаётся зашифрованным; не распаковывать.
sha256sum BroSec-*.zip
printf 'Каталог результата: %s\n' "$run"
SH`

const gpoScript = String.raw`# Collect-BroSec.ps1 — подпишите доверенным code-signing сертификатом после адаптации.
# Разместите скрипт в защищённом SYSVOL; бинарник НЕ запускается с UNC.
$ErrorActionPreference = 'Stop'
$campaign = 'pilot-20261027' # НОВОЕ значение только для согласованного нового запуска
$source = '\\files.example.org\BroSecTools$\pilot-20261027'
$drop = '\\files.example.org\BroSecEvidence$'
# Замените SHA256 по проверенному manifest.json. Не берите доверенный хеш из writable share.
$expected = 'REPLACE_WITH_64_HEX_SHA256_FROM_APPROVED_MANIFEST'
if ($expected -notmatch '^[a-fA-F0-9]{64}$') { throw 'Сначала укажите проверенный SHA256' }
$root = Join-Path 'C:\ProgramData\BroSec' $campaign
New-Item -ItemType Directory -Path $root -Force | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Ошибка ACL' }
# Эксклюзивный файловый lock освобождается ОС даже после аварии процесса.
$lock = [IO.File]::Open((Join-Path $root 'run.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $done = Join-Path $root 'collected.ok'
    $sent = Join-Path $root 'transferred.ok'
    $out = Join-Path $root 'output'
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    if (-not (Test-Path $done)) {
        # После неполного запуска не смешивать старые результаты с новыми.
        if (@(Get-ChildItem $out -Force).Count -gt 0) { throw 'Есть незавершённый запуск; требуется ручная проверка' }
        $exe = Join-Path $root 'BroSec-Collector.exe'
        Copy-Item "$source\BroSec-Collector.exe" $exe
        if ((Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) {
            throw 'SHA256 mismatch'
        }
        Push-Location $out
        try {
            & $exe *> .\collector.log
            if ($LASTEXITCODE -ne 0) { throw 'Collection failed' }
            if (@(Get-ChildItem -File -Filter 'BroSec-*.zip').Count -ne 1) { throw 'Нет единственного ZIP' }
            New-Item -ItemType File -Path $done | Out-Null
        } finally { Pop-Location }
    }
    if (-not (Test-Path $sent)) {
        # Администратор ЗАРАНЕЕ создаёт campaign\COMPUTERNAME с индивидуальной NTFS ACL.
        $target = Join-Path (Join-Path $drop $campaign) $env:COMPUTERNAME
        if (-not (Test-Path $target)) { throw 'Нет индивидуального каталога приёма' }
        $zip = Get-ChildItem $out -File -Filter 'BroSec-*.zip'
        $remote = Join-Path $target $zip.Name
        Copy-Item $zip.FullName ($remote + '.partial') -Force
        if ((Get-FileHash $zip.FullName).Hash -ne (Get-FileHash ($remote + '.partial')).Hash) {
            throw 'Проверка копии не пройдена'
        }
        Move-Item ($remote + '.partial') $remote -Force
        New-Item -ItemType File -Path $sent | Out-Null
    }
} finally { $lock.Dispose() }`

const installUbuntu = String.raw`# Управляющий Linux-узел, Ubuntu 22.04/24.04; поддерживаемый пакет из репозитория ОС.
sudo apt-get update
sudo apt-get install -y ansible openssh-client python3
ansible --version`
const installRhel = String.raw`# Управляющий Linux-узел, RHEL 9 с действующей подпиской и разрешёнными репозиториями.
# ansible-core — базовые модули playbook ниже; EPEL и curl | bash не требуются.
sudo dnf install -y ansible-core openssh-clients python3
ansible --version
# Если пакета нет: администратор проверяет подписку/доступ к AppStream.
# Не подключайте случайные внешние репозитории.`
const sshSetup = String.raw`# Выполняет оператор на управляющем узле; passphrase введите интерактивно.
umask 077
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/brosec_triage -C brosec-triage
# Если политика FIPS запрещает Ed25519, согласуйте RSA 3072+ вместо обхода политики.
ssh-copy-id -i ~/.ssh/brosec_triage.pub triage@linux-pilot.example.org
# Сверьте host fingerprint по независимому каналу. Не используйте StrictHostKeyChecking=no.
ssh -i ~/.ssh/brosec_triage triage@linux-pilot.example.org 'id; python3 --version'
# На целевых узлах: Python 3, sudo и одобренное право become для triage.
# Не выдавайте бессрочный NOPASSWD:ALL ради инструкции.`
const inventory = String.raw`# inventory.ini: сначала ОДИН тестовый узел; имена — буквы, цифры, _ и -.
[triage_pilot]
linux-pilot ansible_host=linux-pilot.example.org

[triage_pilot:vars]
ansible_user=triage
ansible_ssh_private_key_file=~/.ssh/brosec_triage
ansible_python_interpreter=/usr/bin/python3
# Секретов здесь нет. Разные become-пароли — разделите группы или используйте Ansible Vault.`
const playbook = String.raw`# collect.yml — пакет Linux уже распакован рядом: package/BroSec-Collector + manifest.json.
# Отдельный run_id для каждой волны; не повторяйте его после частичного сбора.
- name: BroSec offline collection (no upload API)
  hosts: triage_pilot
  gather_facts: false
  become: true
  serial: 2
  any_errors_fatal: true
  vars:
    stage: "/var/lib/brosec/{{ run_id }}/{{ inventory_hostname }}"
    binary_sha256: "{{ (lookup('file', 'package/manifest.json') | from_json).executable_sha256 }}"
  pre_tasks:
    - name: Validate safe names and explicit wave identifier
      ansible.builtin.assert:
        that:
          - run_id is defined
          - run_id is match('^[A-Za-z0-9_-]{1,64}$')
          - inventory_hostname is match('^[A-Za-z0-9_-]{1,64}$')
          - binary_sha256 is match('^[a-f0-9]{64}$')
    - name: Check source integrity on controller
      ansible.builtin.stat:
        path: "{{ playbook_dir }}/package/BroSec-Collector"
        checksum_algorithm: sha256
      delegate_to: localhost
      become: false
      register: source_binary
    - name: Require matching approved manifest
      ansible.builtin.assert:
        that: source_binary.stat.checksum == binary_sha256
    - name: Refuse mixing with any previous run
      ansible.builtin.stat:
        path: "{{ stage }}"
      register: previous_run
    - name: Require a fresh output directory
      ansible.builtin.assert:
        that: not previous_run.stat.exists
  tasks:
    - name: Create protected parent directories
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        owner: root
        group: root
        mode: '0700'
      loop:
        - /var/lib/brosec
        - "/var/lib/brosec/{{ run_id }}"
        - "{{ stage }}"
    - name: Copy approved collector
      ansible.builtin.copy:
        src: package/BroSec-Collector
        dest: "{{ stage }}/BroSec-Collector"
        owner: root
        group: root
        mode: '0700'
    - name: Check remote SHA256
      ansible.builtin.stat:
        path: "{{ stage }}/BroSec-Collector"
        checksum_algorithm: sha256
      register: remote_binary
    - name: Reject changed binary
      ansible.builtin.assert:
        that: remote_binary.stat.checksum == binary_sha256
    - name: Execute embedded profile WITHOUT invented CLI flags
      ansible.builtin.command:
        argv: ["{{ stage }}/BroSec-Collector"]
        chdir: "{{ stage }}"
      async: 3900
      poll: 10
      register: collection
      failed_when: false
      no_log: true
    - name: Restrict evidence and diagnostic file modes after execution
      ansible.builtin.file:
        path: "{{ stage }}"
        state: directory
        recurse: true
        mode: 'u=rwX,go='
    - name: Preserve protected collector diagnostics on target
      ansible.builtin.copy:
        content: "{{ collection | to_nice_json }}"
        dest: "{{ stage }}/ansible-collection.json"
        mode: '0600'
      no_log: true
    - name: Require successful collection before fetching
      ansible.builtin.assert:
        that: (collection.rc | default(-1)) == 0
        fail_msg: 'Collection failed; inspect protected target diagnostics, do not rerun same run_id.'
    - name: Find encrypted output in this host directory only
      ansible.builtin.find:
        paths: "{{ stage }}"
        patterns: 'BroSec-*.zip'
        file_type: file
        recurse: false
      register: evidence
    - name: Require one output archive
      ansible.builtin.assert:
        that: evidence.matched == 1
    - name: Fetch encrypted ZIP over SSH; per-host controller path
      ansible.builtin.fetch:
        src: "{{ item.path }}"
        dest: "{{ playbook_dir }}/evidence/{{ run_id }}/{{ inventory_hostname }}/"
        flat: true
        validate_checksum: true
      loop: "{{ evidence.files }}"
      no_log: true`
const runAnsible = String.raw`# На контроллере: ограничьте каталог проекта и результатов ДО запуска.
umask 077
chmod 0700 .
mkdir -p evidence
chmod 0700 evidence
ansible-inventory -i inventory.ini --graph
ansible triage_pilot -i inventory.ini -m ansible.builtin.ping --limit linux-pilot
ansible triage_pilot -i inventory.ini -b -K -m ansible.builtin.command -a 'id' --limit linux-pilot
ansible-playbook -i inventory.ini collect.yml --syntax-check -e run_id=pilot_20261027_01
# Это реальный запуск: только после согласования, проверки свободного места и окна работ.
ansible-playbook -i inventory.ini collect.yml --limit linux-pilot --forks 2 -K -e run_id=pilot_20261027_01
# После приёмки пилота добавьте ТОЛЬКО согласованные узлы в группу и задайте НОВЫЙ run_id:
# ansible-playbook -i inventory.ini collect.yml --forks 2 -K -e run_id=wave_20261028_01
# Не используйте --check как доказательство успешного сбора: он не выполняет collector.`

type GuideTab = "prepare" | "single" | "gpo" | "ansible" | "import"
const tabs: { id: GuideTab; label: string; caption: string }[] = [
  { id: "prepare", label: "1. Создать сборщик", caption: "Профиль и доверие" },
  { id: "single", label: "2. Один хост", caption: "Windows / Linux" },
  { id: "gpo", label: "3. Windows · GPO", caption: "Пилот → волны" },
  { id: "ansible", label: "4. Linux · Ansible", caption: "Установка → fetch" },
  { id: "import", label: "5. Импорт", caption: "ZIP → анализ" },
]

function Command({ title, code }: { title: string; code: string }) {
  const [status, setStatus] = useState("")
  async function copy() {
    try { await navigator.clipboard.writeText(code); setStatus("Скопировано") }
    catch { setStatus("Буфер недоступен: выделите и скопируйте код вручную") }
  }
  return <div className="my-4 overflow-hidden rounded-xl border bg-background">
    <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/40 px-4 py-2"><span className="text-xs font-medium">{title}</span><Button type="button" size="sm" variant="outline" onClick={() => void copy()} aria-label={`Копировать: ${title}`}>Копировать</Button></div>
    <pre className="max-h-[34rem] overflow-auto p-4 text-xs leading-relaxed" tabIndex={0} aria-label={title}><code>{code}</code></pre>
    <p role="status" aria-live="polite" className="px-4 pb-2 text-xs text-muted-foreground">{status || "Команды не выполняются из интерфейса. Сначала прочитайте условия и замените примеры."}</p>
  </div>
}
function Step({ title, children }: { title: string; children: ReactNode }) {
  return <section className="space-y-3 rounded-xl border bg-card p-4 sm:p-5"><h3 className="font-semibold">{title}</h3><div className="space-y-3 text-sm leading-relaxed text-muted-foreground">{children}</div></section>
}
function Disclosure({ title, children }: { title: string; children: ReactNode }) {
  return <details className="rounded-xl border p-4"><summary className="cursor-pointer text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring">{title}</summary><div className="mt-3 space-y-3 text-sm leading-relaxed text-muted-foreground">{children}</div></details>
}

/** Read-only deployment instructions: no API requests, credentials or endpoint execution. */
export function HuntingCollectionGuide({ className = "" }: { className?: string }) {
  const [tab, setTab] = useState<GuideTab>("prepare")
  const id = useId()
  return <section className={`space-y-5 ${className}`} aria-label="Пошаговая инструкция по сбору Threat Hunting">
    <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3"><div><p className="text-xs font-semibold uppercase text-muted-foreground">Инструкции по сбору</p><p className="text-sm text-muted-foreground">Пошаговые сценарии доставки и безопасного запуска</p></div><a href="/api/threat-hunting/manual.pdf" className="inline-flex min-h-10 items-center gap-2 rounded-md border px-3 text-sm hover:bg-muted"><FileDown className="size-4" aria-hidden="true"/>PDF · полное руководство</a></div>
    <header className="rounded-2xl border bg-gradient-to-br from-primary/10 via-card to-card p-5 sm:p-6">
      <p className="text-xs font-medium uppercase tracking-widest text-primary">Практическое руководство · offline collection</p>
      <h2 className="mt-2 text-xl font-semibold tracking-tight sm:text-2xl">От сборщика до проверенного результата</h2>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">Сначала один согласованный хост, затем пилотная OU или inventory и только потом небольшие волны. GPO и Ansible доставляют и запускают сборщик; импорт в BroSec — отдельный шаг.</p>
      <div className="mt-4 flex flex-wrap gap-2 text-xs">{["Без паролей в скриптах", "Зашифрованный ZIP", "Индивидуальный каталог хоста", "Никакого автоматического развёртывания"].map(label => <span key={label} className="rounded-full border bg-background/80 px-3 py-1">{label}</span>)}</div>
    </header>
    <div className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4 text-sm leading-relaxed"><strong>Граница безопасности.</strong> Нужны разрешение владельца, окно работ, резерв свободного места и проверка EDR. Не отключайте защиту, не меняйте ExecutionPolicy на Bypass, не размещайте приватные ключи расшифрования на конечных узлах. Примеры содержат только фиктивные домены и требуют адаптации.</div>
    <nav aria-label="Разделы инструкции" className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">{tabs.map(item => <button key={item.id} type="button" id={`${id}-${item.id}`} aria-pressed={tab === item.id} aria-controls={`${id}-content`} onClick={() => setTab(item.id)} className={`rounded-xl border p-3 text-left transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring ${tab === item.id ? "border-primary/50 bg-primary/10 text-foreground" : "bg-card text-muted-foreground hover:bg-muted"}`}><span className="block text-sm font-semibold">{item.label}</span><span className="mt-1 block text-xs">{item.caption}</span></button>)}</nav>
    <div id={`${id}-content`} role="region" aria-labelledby={`${id}-${tab}`} className="space-y-4">
      {tab === "prepare" && <>
        <Step title="01 / Согласуйте объём и выберите компанию"><p>Откройте Threat Hunting → «Сборщики», выберите правильную компанию. Согласуйте перечень хостов, владельца данных, срок хранения, окно работ, объём свободного диска и разрешение привилегированного запуска. Контроллеры домена и критичные серверы не включайте в первый пилот.</p></Step>
        <Step title="02 / Создайте отдельный профиль для каждой ОС"><p>Укажите название, ОС и лимит времени: допустимо 60–3600 секунд, для пилота начните с 300–600 секунд. Реально упаковываются: Linux — сведения об ОС, процессы, соединения; Windows — те же сборы плюс службы, задания и автозапуск. Пункты-кандидаты в каталоге не означают готовую поддержку упаковки.</p><p>Сетевые данные — снимок, не история. Поле окна событий не превращает baseline в сбор EVTX: текущая упаковка журналов событий не поддерживается. Лимиты строк могут усекать данные; отсутствие находки не доказывает отсутствие компрометации.</p></Step>
        <Step title="03 / Скачайте ZIP и проверьте происхождение"><p>Сохраните профиль → «Скачать сборщик». В ZIP: <code>BroSec-Collector.exe</code> для Windows либо <code>BroSec-Collector</code> для Linux и <code>manifest.json</code>. JSON спецификации профиля — не исполняемый сборщик. Если кнопка недоступна, проверьте поддерживаемые сборы и установку доверенного упаковщика на сервере.</p><p>Распакуйте пакет в отдельный защищённый каталог. Сохраните manifest и сверяйте SHA256 с <code>executable_sha256</code>; доверенный хеш фиксируйте из авторизованной загрузки, а не из общей папки с правом записи для клиентов. Уточните архитектуру бинарника: поле ОС само по себе не гарантирует совместимость CPU.</p></Step>
        <Disclosure title="Что действительно делает встроенный профиль"><p>Это offline Velociraptor с autoexec: запускается сам бинарник без дополнительных флагов. Он создаёт <code>BroSec-&lt;Hostname&gt;-&lt;timestamp&gt;.zip</code> в текущем рабочем каталоге. Встроены timeout профиля, <code>progress_timeout=120</code>, <code>cpu_limit=20</code>, <code>concurrency=1</code>. CPU-параметр — ограничитель движка, не гарантированный лимит ОС; квоты RAM/размера результата не настроены.</p><p>Windows требует административных прав. Пакет помечен <code>execution_verified=false</code>: целевой запуск проверяется пилотом, а не обещанием интерфейса. Не добавляйте выдуманные <code>--output</code>, <code>--upload</code> или токены. Профиль и сертификат уже внутри бинарника.</p></Disclosure>
      </>}
      {tab === "single" && <>
        <Step title="01 / Windows: один хост, повышенный PowerShell"><p>Распакуйте Windows-пакет в <code>C:\BroSec\package</code>; изменять этот каталог должны только администраторы и SYSTEM. Убедитесь, что достаточно места и запуск согласован с EDR. Откройте PowerShell «Запуск от имени администратора», проверьте хеш, создайте каталог хоста и запустите бинарник без аргументов. Права ниже задаются через SID и не зависят от языка Windows.</p><Command title="Windows · проверка и локальный сбор" code={windowsRun} /><p>Результат и журнал находятся в выведенном каталоге <code>C:\ProgramData\BroSec\Evidence\&lt;HOST&gt;-&lt;time&gt;</code>. Сам журнал не зашифрован: сохраняйте его под защищённой ACL, не прикладывайте в публичные тикеты.</p></Step>
        <Step title="02 / Linux: один хост, root через sudo"><p>Нужны совместимый Linux-бинарник, Python 3 для сверки manifest и разрешённый sudo. Передайте пакет по SSH/SCP в защищённое место; не выполняйте содержимое общедоступной папки. Сначала проверьте hash, затем запретите непривилегированную запись в каталог и все его родительские каталоги. Не запускайте одновременно от нескольких операторов.</p><Command title="Linux · проверка и локальный сбор" code={linuxRun} /><p>Если SHA256, права, код завершения или наличие архива не прошли проверку — остановитесь. При ошибке не удаляйте следы и не повторяйте сбор бесконечно: изучите защищённый журнал и согласуйте новый каталог запуска.</p></Step>
        <Step title="03 / Верните результат аналитику"><p>Копируйте только итоговый зашифрованный ZIP и его SHA256 по утверждённому защищённому каналу. Сохраняйте соответствие «компания → профиль → хост → время → хеш». Не путайте исходный ZIP со сборщиком и полученный ZIP с evidence. Перейдите к шагу «Импорт».</p></Step>
      </>}
      {tab === "gpo" && <>
        <Step title="01 / Создайте пилотную область, а не доменное развёртывание"><p>В GPMC создайте новую GPO «BroSec — pilot collection» и свяжите её только с тестовой OU с 1–2 некритичными компьютерами. Не редактируйте Default Domain Policy и Default Domain Controllers Policy. В Security Filtering выдайте Read + Apply Group Policy отдельной группе <em>компьютерных</em> аккаунтов пилота; сохраните необходимые права чтения GPO для компьютеров (например, Domain Computers: Read без Apply). Проверьте наследование, deny, WMI-фильтры и результирующую политику.</p><p>После изменения членства компьютерной группы может потребоваться обновление машинного Kerberos-токена при согласованной перезагрузке. Не распространяйте GPO на DC и не выполняйте принудительную массовую перезагрузку.</p></Step>
        <Step title="02 / Разделите доставку и приём результатов"><p><strong>Источник:</strong> отдельная SMB-share <code>\\files.example.org\BroSecTools$</code>, запись только у ответственных администраторов, пилотным компьютерным аккаунтам — Read на уровне share и NTFS. Не разрешайте клиентам менять бинарник, manifest или startup-скрипт: это удалённый запуск от SYSTEM.</p><p><strong>Приём:</strong> отдельная share <code>\\files.example.org\BroSecEvidence$</code>. Администратор заранее создаёт <code>pilot-20261027\HOSTNAME</code> для каждого хоста: только <code>DOMAIN\HOSTNAME$</code> — Modify на своём каталоге, группа аналитиков — Read, администраторы — Full Control. Уберите унаследованные широкие права: ни Domain Computers, ни Everyone не должны читать/менять чужие каталоги. На share выдавайте Change лишь группе пилотных машин и Read аналитикам; NTFS дополнительно ограничивает каждый каталог. Разрешите лишь необходимый traverse к родителям; проверьте фактический доступ именно под машинной учётной записью.</p><p>Startup выполняется от Local SYSTEM и обращается к сети как <code>DOMAIN\COMPUTER$</code>, а не как вошедший пользователь. Не кладите пароли в GPO, не используйте mapped drives, guest/anonymous SMB и общую папку с Everyone:Full Control. Доступ по прямому UNC, Kerberos, SMB signing/encryption — по политике организации; символ <code>$</code> в имени share не является защитой.</p></Step>
        <Step title="03 / Подготовьте одноразовый startup-скрипт"><p>Сначала пройдите ручной Windows-пилот. Скопируйте одобренный бинарник в versioned read-only источник. В шаблоне замените домен, campaign и доверенный SHA256. Подпишите скрипт сертификатом, доверенным на пилотных ПК; не обходите AppLocker/WDAC/ExecutionPolicy. Вывод пишется локально, затем ZIP копируется в собственный каталог хоста; при сетевой ошибке следующий старт повторяет только доставку. Незавершённый сбор требует ручного разбора, а не автоматической перезаписи.</p><Command title="GPO · шаблон Collect-BroSec.ps1 (адаптировать и подписать)" code={gpoScript} /></Step>
        <Step title="04 / Привяжите скрипт к Computer Startup"><ol className="list-decimal space-y-2 pl-5"><li>GPO → Computer Configuration → Policies → Windows Settings → Scripts (Startup/Shutdown) → Startup → PowerShell Scripts. Через Show Files разместите подписанный скрипт в защищённом каталоге этой GPO; Add → выберите скрипт. Бинарник храните отдельно, не раздувайте SYSVOL.</li><li>Согласуйте «Always wait for the network at computer startup and logon» в Computer Configuration → Policies → Administrative Templates → System → Logon. При необходимости startup policy processing wait time и синхронный startup настраиваются только в пилоте: это может замедлить загрузку.</li><li>В System → Scripts согласуйте Maximum wait time for Group Policy scripts: значение должно превышать timeout профиля плюс доставку и запас, например 900 секунд для профиля 600 секунд; не задавайте бесконечное ожидание. Загрузочное окно — не инструмент для долгого forensic-сбора.</li><li>На пилотном ПК выполните <code>gpupdate /target:computer</code>, проверьте <code>gpresult /scope computer /r</code>. Startup запускается при следующей согласованной перезагрузке, не просто от gpupdate. Проверьте GroupPolicy/Operational и PowerShell журналы без публикации чувствительных данных.</li><li>После загрузки проверьте локальный collected.ok, transferred.ok, итоговый ZIP и совпадение SHA256 на сервере. Проверьте также, что HOST-A$ не имеет доступа к результатам HOST-B$. Имитируйте недоступность share на тестовом узле и убедитесь, что повторная доставка не запускает сбор заново.</li></ol></Step>
        <Step title="05 / Масштабируйте волнами и завершите rollout"><p>GPO сама не ограничивает число одновременно стартующих компьютеров. Используйте отдельные небольшие группы/OU, окна перезагрузки и проверку каждой волны; оценивайте нагрузку диска, CPU, сети и SMB. При деградации остановите добавление хостов. Для новой кампании используйте новый идентификатор и отдельные каталоги/ACL, не удаляйте markers для бесконтрольного повторного запуска.</p><p>После приёмки результатов отключите startup-скрипт или снимите link этой GPO, проверьте прекращение запуска, отзовите временные права SMB. Локальные файлы удаляйте только после подтверждённого импорта и по retention-политике. Копирование в share не означает импорт или завершение аналитики.</p></Step>
      </>}
      {tab === "ansible" && <>
        <Step title="01 / Установите Ansible на управляющий Linux-узел"><p>Ansible ставится на контроллер, не на каждый endpoint. Контроллер должен иметь SSH-доступ к целевым Linux-хостам; целям нужны Python 3, sudo и совместимая архитектура сборщика. Для иной версии ОС сначала проверьте поддерживаемые репозитории и версию ansible-core.</p><Command title="Контроллер · Ubuntu" code={installUbuntu} /><Command title="Контроллер · RHEL 9" code={installRhel} /></Step>
        <Step title="02 / Настройте SSH и проверяемый become"><Command title="SSH-ключ и проверка доступа" code={sshSetup} /><p>Храните приватный SSH-ключ только на контроллере с mode 0600, используйте passphrase/ssh-agent по политике. Пароль sudo запрашивается через <code>-K</code>, не хранится в inventory или командной строке. Если используется Vault, храните vault secret отдельно. Стандартный Ansible become выполняет модули от root: узкий sudo allowlist для одного бинарника с этим playbook не эквивалентен; права должен согласовать администратор.</p><p>SSH в Ansible не настраивайте на отключение host key checking. Для недоступных Python/sudo хостов используйте утверждённое управление конфигурацией, не bootstrap со случайного URL.</p></Step>
        <Step title="03 / Создайте закрытый рабочий каталог и пилотный inventory"><p>В отдельном каталоге контроллера сохраните <code>inventory.ini</code>, <code>collect.yml</code> и распакованный Linux-пакет в <code>package/</code>. Только оператору разрешена запись. Проверяйте загруженный manifest по доверенному каналу, не подменяйте его файлом от endpoint. Удостоверьтесь в запасе места на каждой цели и контроллере: fetch через become может использовать дополнительную память/трафик для checksum.</p><Command title="inventory.ini · только пилотные хосты" code={inventory} /></Step>
        <Step title="04 / Копирование → запуск → fetch, по два хоста"><p>Playbook создаёт уникальный каталог <code>/var/lib/brosec/&lt;run_id&gt;/&lt;inventory_hostname&gt;</code>, сверяет SHA256, запускает настоящий бинарник без аргументов, проверяет код возврата и забирает один зашифрованный ZIP по SSH. Внешний async 3900 секунд даёт запас над максимумом профиля 3600 секунд. Это не quota диска/RAM; контролируйте ресурсы отдельно. При первой ошибке дальнейшие партии останавливаются; уже запущенные задачи текущей партии могут завершиться.</p><Command title="collect.yml · ограниченный массовый сбор Linux" code={playbook} /></Step>
        <Step title="05 / Проверьте доступ, выполните один пилот, затем волну"><Command title="Проверка и согласованный запуск Ansible" code={runAnsible} /><p>Результаты на контроллере: <code>evidence/&lt;run_id&gt;/&lt;inventory_hostname&gt;/BroSec-*.zip</code>. Проверьте число ожидаемых хостов, размеры и SHA256; каталоги приватные благодаря umask 077 и закрытому родителю. Не делайте один общий ZIP всех хостов вместо оригинальных encrypted evidence. Отправьте каждый результат на импорт отдельно.</p><p>Playbook не удаляет endpoint evidence автоматически и не загружает его в API. При ошибке защищённая диагностика остаётся на цели; не переиспользуйте run_id для обхода проверки. Возобновляйте согласованной новой волной только неуспешные хосты. После подтверждённого импорта удалите локальные копии на целях/контроллере по retention и отзовите временные SSH/sudo-права.</p></Step>
      </>}
      {tab === "import" && <>
        <Step title="01 / Сохраните encrypted evidence неизменным"><p>На каждом хосте ожидается оригинальный <code>BroSec-&lt;Hostname&gt;-&lt;timestamp&gt;.zip</code>. Случайный пароль архива защищён публичным X509-сертификатом компании; сервер использует соответствующий приватный ключ при импорте. Пароль вводить оператору не нужно. Не распаковывайте/переупаковывайте ZIP и не распространяйте серверный keypair. Сохраняйте резервную копию ключей по защищённой процедуре: их потеря делает старые результаты нечитаемыми.</p></Step>
        <Step title="02 / Импортируйте в ту же компанию"><ol className="list-decimal space-y-2 pl-5"><li>В Threat Hunting выберите исходную компанию и откройте загрузку результатов/импорты.</li><li>Выберите <strong>итоговый ZIP evidence</strong>, а не ZIP с бинарником и manifest. По одному архиву хоста, не более 128 МиБ.</li><li>Нажмите «Проверить и сохранить» и дождитесь подтверждения. Проверьте хост, количество строк, ошибки валидации и доступность forensic evidence.</li><li>Отдельно проверьте статус анализа и исходные строки. Принятый сбор не равен завершённой аналитике; пустая таблица не равна чистому хосту.</li></ol><p>Действуют дополнительные серверные ограничения: распакованный объём до 512 МиБ, до 2000 файлов и до 100000 строк. Не обходите лимит делением/переупаковкой encrypted ZIP: согласуйте меньший профиль или изменение сервиса.</p></Step>
        <Step title="03 / Различайте три независимых этапа"><p><strong>Staged collection:</strong> GPO/Ansible → бинарник → локальный encrypted ZIP → share/fetch. <strong>Импорт:</strong> оператор отправляет ZIP в BroSec и проверяет принятие. <strong>Анализ:</strong> обработка результата и решение аналитика. Ни этот guide, ни показанные скрипты не выполняют автоматический API-upload.</p><p>Создание кампании в UI само по себе не устанавливает агент и не запускает GPO/SSH. У обычного скачанного профиля campaign metadata по умолчанию <code>manual</code>; наличие кампании не делает архив автоматически связанным с её задачей. API умеет упаковку с campaign_id, но выдачу задач, lease, транспорт и task/result binding нужно интегрировать отдельно по серверному контракту, а не придумывать параметры бинарника.</p></Step>
        <Disclosure title="Если что-то пошло не так"><ul className="list-disc space-y-2 pl-5"><li>Нет бинарника или кнопка неактивна: упаковщик/профиль не поддержан, JSON спецификации запускать нельзя.</li><li>Нет ZIP: проверьте cwd, права, код возврата, timeout, EDR и защищённый журнал. Не отключайте EDR ради повторной попытки.</li><li>GPO не запускается: проверьте область OU, machine-group token, Read/Apply GPO, сетевое ожидание, подпись и машинный доступ к UNC.</li><li>Нет доступа к SMB: проверяйте share + NTFS как DOMAIN\HOST$, не как администратор или пользователь desktop-сессии.</li><li>Импорт отклонён: проверьте исходную компанию, целостность ZIP, серверный ключ и лимиты; сохраните оригинал, не пытайтесь угадывать пароль.</li></ul></Disclosure>
      </>}
    </div>
    <footer className="flex flex-wrap items-center justify-between gap-3 border-t pt-4 text-xs text-muted-foreground"><p>Инструкция не запускает сбор и не отправляет данные. Все примеры сначала проверяются в пилоте.</p><div className="flex gap-2"><Button type="button" size="sm" variant="outline" disabled={tab === "prepare"} onClick={() => setTab(tabs[tabs.findIndex(item => item.id === tab) - 1].id)}>Назад</Button><Button type="button" size="sm" disabled={tab === "import"} onClick={() => setTab(tabs[tabs.findIndex(item => item.id === tab) + 1].id)}>Далее</Button></div></footer>
  </section>
}
