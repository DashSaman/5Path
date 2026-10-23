# برنامهٔ پیاده‌سازی پذیرش مشترک TCP آلمان — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. اجرای پیشنهادی مستقیم و مرحله‌ای در همین جلسه است؛ تفویض تازه یا controller موازی لازم نیست.

**Goal:** ساخت نامزد صرفاً محلی که دو front آینده را به یک بودجهٔ اتمی K=4096 متصل کند، بدون relay داده و بدون نصب روی سرور.

**Architecture:** یک broker محلی Python، دفتر رزرو SQLite را مدیریت می‌کند و دو client در Python/Go از طریق Unix socket کنترل با آن ارتباط دارند. هر listener پیش از accept یک token رزرو می‌کند؛ تا پایان کامل اتصال نگه می‌دارد. خطای کنترل، پذیرش تازه را می‌بندد؛ جریان‌های دارای token ادامه می‌یابند.

**Tech Stack:** Linux، Python 3.12 و sqlite3 استاندارد، Unix stream/SO_PEERCRED، Go 1.25.5 scoped موجود، sing-box v1.14.3 از commit `7054cac5124465ffdb145870d7c01885566711b1`، unittest و آزمون واقعی loopback در namespace مستقل.

**Spec:** [مشخصات تأییدشدهٔ مالک](../specs/2026-10-23-de-shared-admission-design.fa.md)، blob `62a9303051eb6b3f16b92c11c45e2e676dbd25b1`. مالک فقط نوشتن این plan را مجاز کرده است؛ تمام checkboxهای زیر هنوز اجرا نشده‌اند.

## Global Constraints

- سقف تجمیعی تولیدِ مورد توافق دقیقاً `K=4096` است. N=128/مجموع4224 مجاز نیست. K=3 فقط برای fixture محلی و آزمون عددی4096 بدون4096سوکت است.
- controller/SSH، سرور، T6، XUI، route/DNS/NTP و سرویس committed در دامنهٔ اجرای این plan نیستند. گیت rollout فعلی بسته و بدون bypass می‌ماند.
- `core/mesh_gateway.py`، patch/binary قدیمی و configهای hashed committed درجا تغییر نمی‌کنند؛ نامزد جدید مستقل است.
- مشارکت نسخهٔ Python و native هر دو الزامی است. نسخهٔ فعال قدیمی participant نیست؛ قبولی محلی مجوز هم‌زیستی آن با native در تولید نیست.
- token، TTL ندارد؛ handshake فعلی15s و idle policy فعلی عوض نمی‌شوند. FIN اول یا موفقیت auth جایگاه را آزاد نمی‌کند.
- آزادسازی فقط پس از پایان کامل دو جهت و cleanup handler است؛ تکرارش اثر دوم ندارد. unknown، corruption یا مرگ control ظرفیت تازه ایجاد نمی‌کند.
- داده از همان copy-path می‌رود؛ broker مقصد، payload، credential یا مسیر داده را دریافت نمی‌کند.
- fixture تازه: root/run/nonce/socket/port/deadline مستقل؛ فقط loopback، WAN=0، SSH=0، payload16KiB، حداکثر8فرایند، مجموع512MiB و180s برای آزمون عملکردی. finalizer مستقل فقط فرزندان دقیق همین run را جمع کند.
- دانلود dependency/toolchain یا تغییر go.mod/go.sum ممنوع است. نبود cache یا prerequisite نتیجهٔ توقف ثبت‌شده است؛ ورودی بدون تغییر دوباره build نمی‌شود.
- تکرار سوم روش listener-port، benchmark قبلیِ پاسخ‌گرفته و relay ردشده ممنوع‌اند. حداکثر دو تلاش ناموفق با تغییر علت‌دار برای همین روش جدید؛ سپس توقف با گزارش.

## Review Focus

| حالت حساس | رفتار لازم | محل آزمون |
|---|---|---|
| commit رزرو انجام شده ولی ACK نرسیده | token همچنان اشغال؛ تکرار درخواست، رزرو تازه نسازد | کارهای1و2 |
| لغو accept هم‌زمان با رسیدن اتصال یا FIN یک‌طرفه | مالکیت token گم نشود؛ پیش از cleanup آزاد نشود | کارهای3،4و5 |
| مرگ PID اصلی با فرزند حامل socket | هیچ reclaim تا اثبات خالی‌شدن تمام scope | کارهای2و6 |
| تعویض socket/inode، PID reuse، boot یا schema نامنطبق | ثبت participant و پذیرش تازه رد؛ survivor حفظ | کارهای2،5و6 |
| restart broker هنگام زنده‌بودن participant | نسل FROZEN؛ نه reset، نه reconnect خودکار برای پذیرش | کارهای2و6 |

## تصمیم سازوکار و معنای شمارش

broker + SQLite انتخاب این نامزد است؛ primitive فایل مشترک به fsync/قفل در event loop هر دو front نیاز می‌دهد و بررسی هم‌زمان دو زبان را دشوارتر می‌کند. تنها broker به DB دسترسی نوشتنی دارد. `BEGIN IMMEDIATE`، `journal_mode=WAL`، `synchronous=FULL` و `busy_timeout=0` پس از تنظیم read-back شوند؛ ACK بعد از commit صادر شود. این انتخاب تضمین کارایی یا تحمل خرابی storage نیست و در آزمون قابل رد است.

برای جلوگیری از ایجاد handler یا سوکت پذیرفته‌شدهٔ بدون سهم، هر listener ابتدا یک token می‌گیرد و سپس accept می‌کند؛ حداکثر یک token مصرف‌نشده برای هر listener وجود دارد. این سهم رزروشده هم داخل K است؛ ممکن است تا دو جایگاه از4096 موقتاً بدون جریان واقعی بمانند. سهم idle هرگز با timeout آزاد نمی‌شود: ابتدا accept باید قطع و race آن resolve شود، سپس token بدون socket صریحاً آزاد شود.

در ظرفیت کامل، socketهای اضافه ممکن است در backlog کرنل منتظر بمانند؛ ادعای رد فوری TCP نداریم. N+1 در آزمون یعنی نداشتن token/handshake کاربردی/backend تا وقتی K اشغال است. backlog در fixture برابر8 است و با ظرفیت کاربردی یکی شمرده نمی‌شود.

ناوردای آزمون:
`held = preaccept + running + closing <= K`.
بعد از بستن پذیرش و resolveشدن preacceptها، شمار held باید دقیقاً با handlerهای زنده/درحال cleanup برابر شود. گزارش، این سهم‌های مصرف‌نشده را مخفی یا ظرفیت اضافه قلمداد نکند. handshake معطل جزو running و شمرده است.

قطع broker از لحظهٔ تشخیص control EOF/خطا، پذیرش جدید را می‌بندد؛ ادعای تشخیص آنی crash وجود ندارد. حتی در race تشخیص، token پیشاپیش داخل K رزرو شده و سقف نمی‌شکند. بستن listener فقط accept را متوقف کند و streamهای پذیرفته‌شده را نبندد.

## نقشهٔ فایل‌ها

| فایل آینده | مسئولیت |
|---|---|
| `experimental/shared_admission/{model,store}.py` | schema/شناسه‌ها و دفتر تراکنشی محدود |
| `experimental/shared_admission/{scope,broker,recover}.py` | هویت واقعی peer، سرویس کنترل و بازیابی آفلاین |
| `experimental/shared_admission/{client,legacy}.py` | client غیرمسدودکننده و listener نسل توسعهٔ Gateway |
| `experimental/patches/sing-box-v1.14.3-shared-admission.patch` | patch جدید مستقل؛ patch قبلی حفظ شود |
| `tests/test_shared_admission_*.py` | آزمون‌های مدل، DB و client/listener؛ Linux-only صریح skip شود |
| `integration/{build_shared_admission,shared_admission_fixture,shared_admission_cost}.py` | ساخت تازه از cache، fixture واقعی و سنجش سؤال هزینهٔ جدید |
| `experimental/shared_admission/manifest.py` و `tests/test_shared_admission_manifest.py` | ثبت hashها و تحویل محلیِ غیرقابل نصب |
| `docs/SHARED-ADMISSION-LOCAL.fa.md` و `evidence/shared-admission-local.json` | نتیجهٔ پالایش‌شده، مثبت/منفی و محدودیت‌ها |

همهٔ مسیرها نسبت به ریشهٔ مخزن‌اند. package دارای `__init__.py` باشد؛ test runner فعلی، `experimental/` را به مسیر import اضافه می‌کند.

---

### کار 1: دفتر پایدار و ناوردای سقف

**Files:** ایجاد `model.py`، `store.py` و `tests/test_shared_admission_store.py`.

**Interfaces:**
- `Token(token_id:str, owner:Owner, seq:int)`؛ `Grant(token:Token)`؛ `Full` نتیجهٔ بدون رزرو است؛ state ledger فقط HELD/RELEASED منطقی و خطای مستقل FROZEN دارد.
- `Manifest(schema:int, run_id:str, country:str, k:int, artifact_hashes:dict, allowed_roles:tuple)`
- `Owner(role:str, uid:int, pid:int, start_ticks:int, boot_id:str, cgroup_path:str, cgroup_inode:int)`
- `Ledger.initialize(root:Path, manifest:Manifest) -> Ledger` فقط روی ریشهٔ تازه با O_EXCL؛ `Ledger.open_existing(root, manifest) -> Ledger` هرگز initialize ضمنی نکند.
- `reserve(owner:Owner, seq:int, token_id:str) -> Grant | Full`؛ `release(owner, token_id) -> bool`؛ `held() -> tuple[Token,...]`؛ `freeze(reason:str) -> None`.
- token تصادفی128bit؛ seq افزایشی هر participant در DB. seq قدیمیِ آزادشده REPLAY است؛ تکرار seq فعال همان token را برگرداند؛ هرگز token دوم صادر نشود. DB فقط حداکثرKرکورد held و یک high-water برای هر role نگه دارد، بدون tombstone نامحدود.

- [ ] **1. آزمون قرمز:** fixture روی SQLite فایل واقعی، K=3:
  `assert sum(is_grant(x) for x in concurrent_reserves(4)) == 3`؛
  `assert ledger.reserve(owner, old_seq, old_token) != NEW_GRANT`؛
  `assert release(token) is True; assert release(token) is False`.
  آزمون جدا K=4096 فقط رزرو منطقی4096/4097؛ بدون socket. corruption، disk-full/commit-error و schema/K/hash mismatch هیچ grant/initialize ندهند.
- [ ] **2. مشاهدهٔ شکست:** `rtk proxy python -m unittest discover -s tests -p test_shared_admission_store.py -v`؛ شکست به‌علت نبود رفتار مورد انتظار، نه import/typo اصلاح‌نشده.
- [ ] **3. پیاده‌سازی حداقلی:** transaction سقف+insert و سقف+delete اتمی؛ identity/schema/PRAGMAها read-back؛ خطای storage نسل را freeze کند.
- [ ] **4. همان آزمون سبز:** reopen بعد از commit و پیش از ACK نیز count قبلی را حفظ کند؛ فایل خراب کنار گذاشته یا بازسازی نشود.
- [ ] **5. commit محلی مستقل** با گزارش نتیجه؛ هیچ main push یا Release به‌عنوان نصب تلقی نشود.

### کار 2: broker، peer واقعی و restart امن

**Files:** ایجاد `scope.py`، `broker.py`، `recover.py` و `tests/test_shared_admission_broker.py`.

**Interfaces:**
- `peer_owner(sock:socket.socket, manifest:Manifest) -> Owner` از SO_PEERCRED، /proc، boot و cgroup؛ شناسهٔ ادعایی پیام مرجع نیست.
- `Broker.start(root:Path, manifest:Manifest) -> Broker`؛ `Broker.close_admission(reason:str) -> None`؛ `Broker.close() -> None`.
- `prove_scope_empty(owner:Owner) -> EmptyProof` تنها وقتی همهٔ descendantها/فرزندان و scope دقیق قابل مشاهده و خالی باشند؛ missing/permission/PID-reuse به‌تنهایی proof نیست.
- `recover_generation(root:Path, manifest:Manifest) -> RecoveryReceipt` فقط آفلاین با قفل singleton و proof واقعی تمام scopeها؛ receipt ورودی یا force/reset flag ندارد.

broker پس از start، receipt خصوصیِ root-owned شامل run/boot/PID/start-time/cgroup و manifest hash می‌نویسد؛ client نیز SO_PEERCRED سمت broker و inode مسیر را با همین receipt تطبیق می‌دهد. اعتماد صرف به pathname کافی نیست.

کنترل از Unix SOCK_STREAM با طول2بایتی و JSON حداکثر2048byte است. پیام‌ها REGISTER، RESERVE، RELEASE، CANCEL و DRAIN؛ هر اتصال کنترل یک role مجاز، حداکثر یک RESERVE منتظر ظرفیت و حداکثرKدرخواست release دارد. انتظار ظرفیت event-driven است، بدون polling/retry loop. session از دست‌رفته برای پذیرش خودکار reconnect نمی‌شود. REGISTER به artifact و command/cgroup هویتِ manifest متصل شود؛ مرز اعتماد همان مالک محلی مجاز است، نه مقاومت در برابر root مخرب.

- [ ] **1. آزمون قرمز واقعی Unix socket:** `assert grants_after_commit_before_ack_crash == 1`؛ `assert restart_with_live_scope.state == FROZEN`؛ `assert unregistered_peer_grants == 0`. پیام ناقص/بزرگ، نقش تکراری، socket یا root symlink/inode عوض‌شده، DB busy و schema غلط رد شوند. دومین broker روی همان root نتواند شروع کند.
- [ ] **2. اجرای قرمز و سپس سبز:** `rtk proxy python -m unittest discover -s tests -p test_shared_admission_broker.py -v`؛ Linux-onlyهای اجرا نشده با دلیل ثبت شوند، PASS ساختگی نه.
- [ ] **3. پیاده‌سازی:** singleton lock inode ثابت و root خصوصی؛ broker تنها نویسندهٔ Ledger. قطع peer tokenها را خودکار reclaim نکند. startup روی DB غیرخالیِ دارای owner زنده/نامعلوم FROZEN باشد؛ unlink/truncate/reset ممنوع.
- [ ] **4. آزمون recovery:** PID اصلی ازبین‌رفته ولی فرزند دارای socket زنده → reclaim صفر؛ سپس همهٔ فرزندان reaped و scope دقیق خالی → recovery آفلاین رسید معتبر. boot جدید یا PID reuse بدون proof کافی → رد.
- [ ] **5. commit مستقل.** SIGKILL فقط روی broker/فرزندان fixture دارای PID+start-time ثبت‌شده؛ نه فرایند میزبان ناشناخته.

### کار 3: client و Gateway توسعهٔ Python

**Files:** ایجاد `client.py`، `legacy.py` و `tests/test_shared_admission_legacy.py`. `core/mesh_gateway.py` بدون تغییر.

**Interfaces:**
- `AdmissionClient.connect(socket_path:Path, manifest:Manifest, role:str) -> AdmissionClient` async؛ `reserve() -> Token` async؛ `release(token:Token) -> None` async/idempotent؛ `stop_admitting(reason:str) -> None`.
- `AdmittedGateway(Gateway)` فقط در توسعه، با `start_listener()` و accept-pump مستقل. `handle_admitted(reader, writer, token) -> None` از `serve_socks` و `Gateway.connect` اصلی استفاده کند.
- `AdmissionServer` در همان `legacy.py`، async context manager و `close()`, `async wait_closed()`, `async drain()` داشته باشد: close/wait فقط accept-pump را جمع می‌کنند؛ drain منتظر handlerهای موجود می‌ماند و آن‌ها را اجباری cancel نمی‌کند.
- یک control-reader و accept-pump برای هر listener؛ قبل از token هیچ task اتصال، auth یا upstream ایجاد نشود. release فقط پس از finally کامل `serve_socks`؛ cancellation با token mapping حل شود. core reload config نتواند K/manifest را تغییر دهد.

- [ ] **1. آزمون قرمز:** `assert accepted_without_token == 0`؛ سه pending K=3 سقف را اشغال کنند، چهارمی backend نگیرد؛ `assert held_after_first_fin == before_fin`. payload16KiB قبل و بعد از auth/backend error و control EOF روی دو survivor همان SHA را داشته باشد.
- [ ] **2. اجرای قرمز:** `rtk proxy python -m unittest discover -s tests -p test_shared_admission_legacy.py -v`.
- [ ] **3. پیاده‌سازی:** قبل از `loop.sock_accept` رزرو؛ روی cancel، accept را resolve و socket احتمالی را ببند، سپس unused token را آزاد کن. control loss listener را از پذیرش خارج کند، نه streamهای قبلی را. release بدون ACK همچنان held فرض شود؛ صف/تلاش بی‌انتها ممنوع.
- [ ] **4. اجرای سبز و regression:** auth failure، timeout15s، backend refusal، cancel در هر مرز و first-FIN/final-close؛ افتراقی با `serve_socks` اصلی، event loop بدون SQLite/fsync.
- [ ] **5. commit مستقل.**

### کار 4: client بومی و ساخت تازهٔ pinned

**Files:** patch جدید؛ در منبع sing-box تازه:
`common/listener/shared_admission_client{,_test}.go`،
`option/shared_admission.go`؛ تغییر `option/simple.go`، `common/listener/{listener.go,listener_tcp.go}` و hookهای SOCKS همان مسیر r2.
ایجاد `integration/build_shared_admission.py`.

**Interfaces Go:** `OpenSharedAdmission(ctx context.Context, options SharedAdmissionOptions) (*SharedAdmissionClient,error)`؛ `Reserve(ctx) (Token,error)`؛ `Release(token Token) error`؛ `StopAdmitting(error)`. reader مشترک، seq و قاب دقیق کار2؛ قبل از `Accept` و قبل از goroutine token گرفته شود. onClose یک‌باره فقط پس از بستن conn اصلی و teardown کامل؛ نیم‌بسته‌شدن release ندهد.

گزینهٔ `five_path_shared_admission` صرفاً پیشنهاد API برای همین منبع جدید است؛ تا تعریف در source، compile و `check` در binary جدید معتبر نیست. فعال‌سازی هم‌زمان آن با `five_path_tcp_admission_limit` رد شود؛ K از manifest است، نه override config. users الزامی و detour/UDP/UoT همان‌طور رد شوند. این کلید هرگز به binary/config جاری داده نمی‌شود.

- [ ] **1. تست قرمز Go:** `assert reserve_count_before_accept == 1`؛ callback تکراری فقط یک RELEASE؛ قطع control، Accept مسدود را باز کند ولی دو conn تحویل‌شده SHA را حفظ کنند. timeout/reply malformed و cancel/Accept race بدون unowned socket یا grant اضافی.
- [ ] **2. قرمز سپس سبز روی منبع تازه:** آزمون‌های `./common/listener` و `./protocol/socks` در toolchain cached و network namespace بی‌WAN. نبود cache را ثبت و توقف کن؛ دانلود خودکار نه.
- [ ] **3. پیاده‌سازی و build:** helper SHA pristine/r2/toolchain/go.mod/go.sum را verify کند، کپی مالکیت‌دار تازه بسازد، patch جدید را اعمال و با `-mod=readonly` و compiler/tagهای pinned بسازد. root/binary قبلی overwrite نشود. اگر onClose موجود پیش از پایان تمام route/handler/cleanup اجرا می‌شود و seam معتبر پایان کامل پیدا نشد، همین کار رد شود؛ بستن conn اصلی به‌تنهایی مجوز release نیست.
- [ ] **4. config-check منفی/مثبت در binary تازه:** broker ناموجود/manifest غلط/دو گزینه/بدون users/UDP رد؛ config سالم فقط در fixture. patch، binary، source و logهای کامل در build receipt.
- [ ] **5. commit patch و helper؛ binary/toolchain/private config عمومی نشوند.**

### کار 5: fixture واقعی دو front و lifecycle

**Files:** ایجاد `integration/shared_admission_fixture.py`؛ test utilityهای oracle و finalizer فقط در `integration/`، نه کلاس تولید.

**Interfaces:** `run_case(name:str, build_manifest:Path, out:Path) -> CaseReceipt`؛ `run_all(...) -> Receipt`. manifest و run تازه؛ K=3، Python+native واقعی به یک broker واقعی. oracle مستقلاً tokenهای preaccept/running/closing و handlerهای هر فرایند را با sequence و timestamp ثبت کند؛ ناقص/کهنه یعنی INCOMPLETE.

- [ ] **1. fixture ابتدا روی binary/source بدون اتصال مشترک قرمز شود:** `assert peak_held <= 3` و `assert every_handler_has_unique_token`؛ core/patch تاریخی را mutate نکن. failure باید نشان دهد shared admission وجود ندارد، نه خطای setup.
- [ ] **2. روی نامزد اجرا:** یک run محدود شامل توزیع2+1 بين دوfront، race مرزK، N+1 بدون backend، handshake بی‌بایت، auth/backend/malformed/UDP/UoT failure، FIN دوطرفه، cancel، broker unavailable/corrupt/schema mismatch و control/Accept race. هر failure دو survivor مستقل با SHA/PID/start-time ثابت داشته باشد.
- [ ] **3. assertionها:** `held == preaccept + running + closing <= K`؛ پس از DRAIN و resolve preaccept، `held == live_handlers`؛ پس از پایان تمام جریان‌ها `held == 0`. قبل/بعد counters بدون oracle تازه پذیرش نیست.
- [ ] **4. پاک‌سازی:** `all_owned_children_reaped is True`، namespace/socket/root متعلق به run و finalizer receipt؛ failure هم مدرک دارد. signalهای مورد انتظار از crash test با failure fixture اشتباه نشوند. بیش از دو تلاش علت‌دار نداشته باشد.
- [ ] **5. commit ابزار و گزارش پالایش‌شده؛ لاگ خام/هویت واقعی فقط work.**

### کار 6: ownership، boot و تحویل محلیِ غیرقابل نصب

**Files:** ایجاد `manifest.py`، `tests/test_shared_admission_manifest.py`؛ تکمیل caseهای recovery همان fixture. فایل rollout gate تغییر نکند.

**Interfaces:** `make_local_manifest(artifacts:dict, receipt:Receipt) -> LocalManifest`؛ `validate_local_manifest(manifest, artifacts, receipt) -> None`؛ خروجی همیشه `production_eligible=false` و `rollout_unlocked=false`.

- [ ] **1. آزمون قرمز:** تغییر یک بایت binary/config/policy/broker یا K/boot/participant هویت نامعتبر دهد؛ `assert production_eligible is False` حتی با همهٔ caseهای محلی سبز. nonparticipant legacy یا ورودی ناشناخته receipt قابل نصب نسازد.
- [ ] **2. تست تازهٔ واقعی:** crash owner با فرزند زنده، PID reuse شبیه‌سازی‌شده در identity boundary، boot mismatch، expiry guard و restart broker؛ همهٔ reclaimهای نامعلوم صفر و survivorهای مجاز زنده بمانند.
- [ ] **3. پیاده‌سازی:** manifest به artifactها، root ownership، run/boot، schema، K، ثبت runtime هر دو participant و receiptهای cleanup وصل شود. خروجی summary whitelist و بدون credential باشد. lifecycle محلی به معنی تصویب unit/boot سرور نیست.
- [ ] **4. کنترل gate:** تست موجود/خواندنی نشان دهد CLI و deploy پیش از controller/SSH هنوز RuntimeError گسترش نصب می‌دهند. هیچ flag، fabricated receipt یا اتصال ثبت‌نامی برای بازکردن gate اضافه نشود.
- [ ] **5. commit مستقل.**

### کار 7: سؤال هزینهٔ تازه و جمع‌بندی محدود

**Files:** ایجاد `integration/shared_admission_cost.py`، `docs/SHARED-ADMISSION-LOCAL.fa.md` و `evidence/shared-admission-local.json`.

**Interfaces:** `measure_shared_admission_cost(manifests:dict, out:Path) -> CostReceipt`؛ `verdict(receipt) -> PASS | REJECT | INCONCLUSIVE`.

- [ ] **1. پیش‌ثبت سؤال و معیار:** هزینهٔ کنترل اتصال تازه و CPU تمام اجزای واقعاً اجراشده در old در برابر native+broker؛ همان payload16KiB در هر اتصال، concurrency2، تعداد256اتصال تازه در هر نمونه، ترتیب متوازن6جفت و runtime age یک‌ثانیه‌ای برابر روی loopback. دقت حساب CPU، startup جدا، DB/WAL، RSS/FD و p50/p95/p99 latency رزرو و پایان فایل ثبت شوند؛ worker/watchdog اجرا نشده پوشش «نامعلوم» دارند.
- [ ] **2. تنها پس از سبزشدن کارهای1تا6:** preflight دقت؛ اگر در سقف زمان120s/512MiB دقت کافی نیست، INCONCLUSIVE و توقف؛ اندازهٔ workload را پس از دیدن نتیجه بالا نبر. هزینهٔ measured-stack نباید بیشتر از old با احتساب دقت مشاهده‌شده باشد؛ همپوشانی عدم قطعیت، پذیرش نیست. آزمون dataplane قبلی را با عنوان تازه تکرار نکن.
- [ ] **3. جمع‌بندی:** حتی PASS محلی فقط همین scope است؛ CPU کل سرور، ظرفیت یا gaming ثابت نمی‌شود. REJECT/INCONCLUSIVE همراه شاهد منفی حفظ شود؛ اصلاح بعدی باید سؤال/کد متفاوت داشته باشد.
- [ ] **4. بررسی نهایی متناسب:** `rtk proxy python tools/run_tests.py` با خروجی کامل؛ `rtk proxy python tools/check_public_tree.py`؛ تست‌های Go و fixtureهای اجراشده با skipها/شکست‌ها گزارش شوند. هیچ test server یا private config را برای CI وارد نکن.
- [ ] **5. تحویل:** گزارش، plan و شواهد را برای review یک‌جا آماده کن. ورود به main طبق مجوز مالک و policy انتشار همان مخزن؛ هر main change Release خودکار جدا و سپس بررسی CI/ZIP واقعی/SHA/CRC/source equality دارد. branch draft خودبه‌خود Release یا نصب نیست.

## معیار پایان و گام بعد

این plan با یک نامزد محلیِ آزموده‌شده یا رسید رد/ابهام علت‌دار پایان می‌یابد. حتی در بهترین نتیجه، انتقال سرویس قدیمیِ غیرparticipant حل‌شده فرض نمی‌شود و گیت DE باز نمی‌شود. برنامهٔ تولید، اگر زمانی راه حفظ جریان‌های جاری اثبات شد، سند و تصمیم جدا خواهد داشت؛ این plan مجوز maintenance، قطع اتصال یا جابه‌جایی کاربران نیست.

اجرای مستقیم در همین جلسه پیشنهاد می‌شود؛ بعد از تأیید plan، هر بار یک کار و گزارش کوتاهِ نتیجه/تغییر واقعی/آزمون/گام بعد. اکنون تمام اجراها pending هستند.

## بازبینی خود برنامه

- هر هدف spec به کار1تا7 یا مرز صریح «انتقال تولید خارج از دامنه» وصل شد.
- reserve قبل از accept انتخاب شد تا هیچ pending پذیرفته‌شدهٔ بدون token ساخته نشود؛ هزینهٔ دو سهم مصرف‌نشده آشکار است.
- ACK گم‌شده، release دوباره، accept/cancel race، control loss، PID/cgroup/boot و corruption آزمون مالک دارند.
- نام‌ها و schema بین Python و Go یکی‌اند؛ configuration آینده فقط متعلق به source/binary آینده است.
- هیچ نصب، کد اجرایی، fixture، build یا benchmark در مرحلهٔ تهیهٔ این سند انجام نشده است.

## منابع قراردادهای پایه

- [SQLite WAL و synchronous](https://www.sqlite.org/wal.html) و [BEGIN IMMEDIATE](https://www.sqlite.org/lang_transaction.html): commit و durability به تنظیم و storage بستگی دارند؛ read-back الزامی است.
- [Python 3.12 loop.sock_accept](https://docs.python.org/3.12/library/asyncio-eventloop.html#asyncio.loop.sock_accept): استفاده از socket غیرمسدودکننده برای کنترل ترتیب accept.
- [Go net.Listener](https://pkg.go.dev/net@go1.25.5#Listener): close کردن listener، Accept را باز می‌کند؛ حفظ streamها جداگانه آزموده شود.
- [Linux Unix socket/SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html): credential از kernel گرفته می‌شود؛ جای PID start-time و scope را نمی‌گیرد.
