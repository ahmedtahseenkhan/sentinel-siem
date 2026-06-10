/* Sentinel SIEM — Arabic (العربية) translation
 * RTL layout, Cairo font, comprehensive UI translation.
 * Dynamic data (alert names, rule text, API responses) stays in English.
 */

const I18N_AR = {
  /* ── Brand ─────────────────────────────────────────────────────────── */
  'CoreNest':                         'كور نِست',
  'Enterprise SIEM · v4.2':           'نظام SIEM المؤسسي · v4.2',
  'Search alerts, hosts, cases…':     'بحث في التنبيهات والأجهزة والحالات…',

  /* ── Sidebar nav ───────────────────────────────────────────────────── */
  'Overview':           'نظرة عامة',
  'Analyse':            'التحليل',
  'Alerts':             'التنبيهات',
  'Discover':           'الاستكشاف',
  'Threat Hunting':     'الصيد التهديدي',
  'MITRE ATT&CK':       'MITRE ATT&CK',
  'Threat Map':         'خريطة التهديدات',
  'Detect':             'الكشف',
  'UEBA':               'تحليل سلوك المستخدم',
  'Risk Scoring':       'تسجيل المخاطر',
  'Detection Studio':   'استوديو الكشف',
  'Respond':            'الاستجابة',
  'Cases':              'الحالات',
  'SOAR Playbooks':     'دفاتر التشغيل الآلي',
  'Ticketing':          'إدارة التذاكر',
  'Endpoints':          'نقاط النهاية',
  'Agents':             'الوكلاء',
  'File Integrity':     'سلامة الملفات',
  'Policy Monitor':     'مراقبة السياسة',
  'Audit Trail':        'سجل المراجعة',
  'Intelligence':       'الاستخبارات',
  'Vulnerabilities':    'الثغرات الأمنية',
  'Identity':           'الهوية',
  'Cloud Monitoring':   'مراقبة السحابة',
  'IT Hygiene':         'نظافة تقنية المعلومات',
  'Compliance':         'الامتثال',
  'Compliance Hub':     'مركز الامتثال',
  'HIPAA':              'HIPAA',
  'Dashboards':         'لوحات المعلومات',
  'My Dashboards':      'لوحاتي',
  'Visualize':          'تصور البيانات',
  'Platform':           'المنصة',
  'Reports':            'التقارير',
  'Notifications':      'الإشعارات',
  'Rules':              'القواعد',
  'Decoders':           'فكّ الترميز',
  'Index Management':   'إدارة الفهارس',
  'Stack':              'البنية التحتية',
  'Data Sources':       'مصادر البيانات',

  /* ── Topbar ────────────────────────────────────────────────────────── */
  'all clear':          'كل شيء طبيعي',
  'active incidents':   'حوادث نشطة',
  'Last 24h':           'آخر 24 ساعة',
  'Last 7d':            'آخر 7 أيام',
  'Last 30d':           'آخر 30 يومًا',
  'UTC':                'UTC',

  /* ── Page headers / badges ─────────────────────────────────────────── */
  'WatchNode fleet':              'أسطول WatchNode',
  'Intel · CVE':                  'استخبارات · CVE',
  'Automation':                   'الأتمتة',
  'Jira · ServiceNow':            'Jira · ServiceNow',
  'Inventory':                    'الجرد',
  'ISO · NIST · SOC 2':           'ISO · NIST · SOC 2',
  'AD · LDAP':                    'AD · LDAP',
  'AWS · Azure · GCP':            'AWS · Azure · GCP',
  'Email · Slack':                'البريد الإلكتروني · Slack',
  'PDF · HTML':                   'PDF · HTML',
  'Sigma · Versions':             'Sigma · الإصدارات',
  'Parsing':                      'التحليل اللغوي',
  'Connections':                  'الاتصالات',
  'OpenSearch':                   'OpenSearch',
  'Authentication':               'المصادقة',
  'SCA':                          'SCA',
  'FIM':                          'FIM',
  'Incident Management':          'إدارة الحوادث',

  /* ── Page subtitles ────────────────────────────────────────────────── */
  'Monitor, manage, and enroll WatchNode agents across your environment':
    'مراقبة وإدارة وتسجيل وكلاء WatchNode في بيئتك',
  'Track open CVEs across endpoints, score by CVSS, and assign remediation':
    'تتبع الثغرات المفتوحة عبر نقاط النهاية وتقييمها وتعيين الإصلاحات',
  'Track, investigate and resolve security incidents':
    'تتبع الحوادث الأمنية والتحقيق فيها وحلها',
  'Automated multi-step response workflows triggered by alerts':
    'سير عمل استجابة آلية متعددة الخطوات يُشغّلها التنبيهات',
  'Create and track tickets in Jira or ServiceNow from alerts and cases':
    'إنشاء وتتبع التذاكر في Jira أو ServiceNow من التنبيهات والحالات',
  'Asset inventory across the fleet — OS, software, processes, and identity':
    'جرد الأصول عبر الأسطول — نظام التشغيل والبرامج والعمليات والهوية',
  'ISO 27001 · NIST CSF · SOC 2 · HIPAA · PCI-DSS — unified compliance posture':
    'ISO 27001 · NIST CSF · SOC 2 · HIPAA · PCI-DSS — وضع الامتثال الموحد',
  'User accounts, groups, and risk scoring from AD/LDAP and alert data':
    'حسابات المستخدمين والمجموعات وتقييم المخاطر من AD/LDAP وبيانات التنبيهات',
  'CloudTrail, Activity Log, and Cloud Logging — unified into Sentinel SIEM':
    'سجلات السحابة الموحدة في Sentinel SIEM',
  'Configure email and Slack alerts for critical security events':
    'تكوين تنبيهات البريد الإلكتروني وSlack للأحداث الأمنية الحرجة',
  'Generate security reports for management and compliance audits':
    'إنشاء تقارير أمنية للإدارة وتدقيق الامتثال',
  'Manage detection rules. Add new rule files or browse existing rules':
    'إدارة قواعد الكشف. إضافة ملفات قواعد جديدة أو تصفح القواعد الموجودة',
  'Manage decoder files for log parsing and field extraction':
    'إدارة ملفات فكّ الترميز لتحليل السجلات واستخراج الحقول',
  'Version-controlled Sigma rule management — edit, validate, diff, and rollback':
    'إدارة قواعد Sigma مع التحكم بالإصدارات — تحرير وتحقق ومقارنة واسترجاع',
  'WatchTower, WatchVault, and OpenSearch connection health':
    'صحة اتصال WatchTower وWatchVault وOpenSearch',
  'Manager API, indexer API, and index pattern configuration':
    'تكوين API المدير وAPI المفهرس وأنماط الفهارس',
  'View and manage indexer indices — health, status, size, and document counts':
    'عرض وإدارة فهارس المفهرس — الصحة والحالة والحجم وعدد المستندات',
  'Monitor file system changes across the fleet in real time':
    'مراقبة تغييرات نظام الملفات عبر الأسطول في الوقت الفعلي',
  'Authentication events, sudo usage, and login activity across the fleet':
    'أحداث المصادقة واستخدام sudo ونشاط تسجيل الدخول',
  'Security Configuration Assessment — policy check results across the fleet':
    'تقييم تهيئة الأمان — نتائج فحص السياسة عبر الأسطول',
  'HIPAA compliance framework — requirements and events':
    'إطار امتثال HIPAA — المتطلبات والأحداث',

  /* ── Overview KPI labels ───────────────────────────────────────────── */
  'Events 24h':                     'الأحداث · 24 ساعة',
  'Critical Alerts':                'التنبيهات الحرجة',
  'Agents Online':                  'الوكلاء المتصلون',
  'Open Cases':                     'الحالات المفتوحة',
  'UEBA Anomalies':                 'شذوذات UEBA',
  'RBA Notables':                   'أحداث RBA البارزة',
  '+events · 24h window':           '+أحداث · نافذة 24 ساعة',
  'no escalations':                 'لا تصعيدات',
  'monitoring fleet':               'مراقبة الأسطول',
  'queue empty':                    'قائمة الانتظار فارغة',
  'within baseline':                'ضمن الحدود الطبيعية',
  'no risk-scored events':          'لا أحداث مُقيَّمة بالمخاطر',
  'idle · 24 h window':             'خامل · نافذة 24 ساعة',

  /* ── Agent summary bar ─────────────────────────────────────────────── */
  'Total':                'المجموع',
  'systems':              'أجهزة',
  'Connected':            'متصل',
  'healthy':              'سليم',
  'Disconnected':         'منقطع',
  'investigate':          'يستدعي التحقيق',
  'Pending':              'قيد الانتظار',
  'enrolment':            'التسجيل',
  'FLEET HEALTH':         'صحة الأسطول',
  'Deploy WatchNode to any machine to start monitoring it in real time. Supports Linux, macOS, and Windows.':
    'نشر WatchNode على أي جهاز لبدء مراقبته فورًا. يدعم Linux وmacOS وWindows.',

  /* ── Tab labels ────────────────────────────────────────────────────── */
  'Playbooks':            'دفاتر التشغيل',
  'Execution History':    'سجل التنفيذ',
  'Dashboard':            'لوحة المعلومات',
  'Controls':             'الضوابط',
  'Events':               'الأحداث',
  'System':               'النظام',
  'Software':             'البرامج',
  'Processes':            'العمليات',
  'Identity':             'الهوية',

  /* ── Common buttons ────────────────────────────────────────────────── */
  'Refresh':              'تحديث',
  'Export':               'تصدير',
  'Export CSV':           'تصدير CSV',
  'Apply filters':        'تطبيق الفلاتر',
  'Apply':                'تطبيق',
  'Add new agent':        'إضافة وكيل',
  'New Case':             'حالة جديدة',
  'New Playbook':         'دفتر تشغيل جديد',
  'Create Ticket':        'إنشاء تذكرة',
  'Generate Report':      'إنشاء تقرير',
  'Add rules file':       'إضافة ملف قواعد',
  'Add decoders file':    'إضافة ملف فكّ ترميز',
  'Test Connection':      'اختبار الاتصال',
  'Test connection':      'اختبار الاتصال',
  'Send Test':            'إرسال اختبار',
  'Sync LDAP':            'مزامنة LDAP',
  'Add User':             'إضافة مستخدم',
  'Cancel':               'إلغاء',
  'Save':                 'حفظ',
  'Close':                'إغلاق',
  'New Schedule':         'جدول زمني جديد',
  '+ New Schedule':       '+ جدول زمني جديد',
  'Run analysis':         'تشغيل التحليل',
  'Configure thresholds': 'تكوين الحدود',
  'Configure scanning':   'تكوين الفحص',
  'Reset filters':        'إعادة تعيين الفلاتر',

  /* ── Filter/search placeholders ────────────────────────────────────── */
  'Search CVE-ID, package, or description…': 'بحث عن CVE أو حزمة أو وصف…',
  'Search by name, ID, OS, environment…':    'بحث بالاسم أو المعرف أو نظام التشغيل…',
  'Search rules…':            'بحث في القواعد…',
  'Search decoders…':         'بحث في فكّ الترميز…',
  'Search indexes…':          'بحث في الفهارس…',
  'Search events…':           'بحث في الأحداث…',
  'Agent…':                   'الوكيل…',
  'File path…':               'مسار الملف…',
  'All agents':               'جميع الوكلاء',
  'All Statuses':             'جميع الحالات',
  'All Priorities':           'جميع الأولويات',
  'All Departments':          'جميع الأقسام',
  'All Providers':            'جميع المزودين',
  'Cluster name (optional)':  'اسم الكلاستر (اختياري)',
  'Enabled only':             'الممكّن فقط',
  'All indexes':              'جميع الفهارس',
  'Show all indexes':         'عرض جميع الفهارس',

  /* ── Severity labels ───────────────────────────────────────────────── */
  'SEVERITY':             'الخطورة',
  'All':                  'الكل',
  'Critical':             'حرج',
  'High':                 'مرتفع',
  'Medium':               'متوسط',
  'Low':                  'منخفض',
  'All severities':       'جميع مستويات الخطورة',
  'CVSS':                 'CVSS',
  'Min':                  'أدنى',
  'Max':                  'أقصى',

  /* ── Table column headers ──────────────────────────────────────────── */
  'STATUS':               'الحالة',
  'NAME / HOSTNAME':      'الاسم / المضيف',
  'AGENT ID':             'معرف الوكيل',
  'OS':                   'النظام',
  'VERSION':              'الإصدار',
  'ALERTS':               'التنبيهات',
  'CRITICAL':             'الحرج',
  'LAST SEEN':            'آخر ظهور',
  'Time':                 'الوقت',
  'Level':                'المستوى',
  'Rule ID':              'معرف القواعد',
  'Description':          'الوصف',
  'Groups':               'المجموعات',
  'Agent':                'الوكيل',
  'Event Type':           'نوع الحدث',
  'Hash':                 'التجزئة',
  'Size':                 'الحجم',
  'Timestamp':            'الطابع الزمني',
  'Action':               'الإجراء',
  'File Path':            'مسار الملف',
  'User':                 'المستخدم',
  'Source IP':            'عنوان IP المصدر',
  'Event':                'الحدث',
  'Rule':                 'القاعدة',
  'Index':                'الفهرس',
  'Health':               'الصحة',
  'Total Size':           'الحجم الكلي',
  'Primary Size':         'حجم الأساسي',
  'Documents':            'المستندات',
  'Deleted':              'المحذوف',
  'Primaries':            'الأساسيات',
  'Replicas':             'النسخ',
  '#':                    '#',
  'Title':                'العنوان',
  'Priority':             'الأولوية',
  'Assignee':             'المكلَّف',
  'Notes':                'الملاحظات',
  'Created':              'تاريخ الإنشاء',
  'Policy':               'السياسة',
  'Total':                'المجموع',
  'Passed':               'اجتاز',
  'Failed':               'فشل',
  'Score':                'الدرجة',
  'Last Scan':            'آخر فحص',
  'Name':                 'الاسم',
  'Type':                 'النوع',
  'Risk score':           'درجة المخاطر',
  'Threshold':            'الحد',
  'Progress':             'التقدم',
  'Notables':             'الأحداث البارزة',
  'Last event':           'آخر حدث',
  'Platform':             'المنصة',
  'OS Name':              'اسم النظام',
  'Kernel':               'النواة',
  'Arch':                 'البنية',
  'Vendor':               'المورد',
  'Package':              'الحزمة',
  'Username':             'اسم المستخدم',
  'Display Name':         'الاسم المعروض',
  'Department':           'القسم',
  'Email':                'البريد الإلكتروني',
  'Status':               'الحالة',
  'Source':               'المصدر',
  'Home':                 'المجلد الرئيسي',
  'Shell':                'الصدفة',
  'Ticket ID':            'معرف التذكرة',
  'Summary':              'الملخص',
  'Provider':             'المزوِّد',
  'Alert':                'التنبيه',
  'Case':                 'الحالة',
  'Created By':           'أنشأه',
  'Execution':            'التنفيذ',
  'Playbook':             'دفتر التشغيل',
  'Runs':                 'مرات التشغيل',
  'Enabled':              'مفعَّل',
  'Duration':             'المدة',
  'Started':              'بدأ في',
  'Trigger Level':        'مستوى التشغيل',
  'Actions':              'الإجراءات',
  'Control ID':           'معرف الضابط',
  'Control Name':         'اسم الضابط',
  'Alerts (period)':      'التنبيهات (الفترة)',
  'Max Severity':         'أقصى خطورة',

  /* ── Section / card headers ────────────────────────────────────────── */
  'ALL AGENTS':                       'جميع الوكلاء',
  'PLAYBOOKS':                        'دفاتر التشغيل',
  'EXECUTION HISTORY':                'سجل التنفيذ',
  'ALL CASES':                        'جميع الحالات',
  'PROVIDER CONFIGURATION':           'تكوين المزوِّد',
  'RECENT TICKETS':                   'التذاكر الأخيرة',
  'VULNERABILITY DETAILS':            'تفاصيل الثغرات',
  'VULNERABILITY TRENDS · 30 DAYS':   'اتجاهات الثغرات · 30 يومًا',
  'TOP 10 AGENTS BY VULNERABILITIES': 'أعلى 10 أجهزة ثغرات',
  'TOP 10 VULNERABLE PACKAGES':       'أعلى 10 حزم ثغرات',
  'RULES LIBRARY':                    'مكتبة القواعد',
  'DECODERS LIBRARY':                 'مكتبة فكّ الترميز',
  'FIM EVENTS TIMELINE · 24H':        'جدول أحداث FIM · 24 ساعة',
  'EVENTS BY ACTION':                 'الأحداث حسب الإجراء',
  'FIM EVENTS':                       'أحداث FIM',
  'AUTHENTICATION ACTIVITY · 24H':    'نشاط المصادقة · 24 ساعة',
  'SUCCESS VS FAILURE':               'نجاح مقابل فشل',
  'AUDIT EVENTS':                     'أحداث التدقيق',
  'RESULTS DISTRIBUTION':             'توزيع النتائج',
  'AGENT COMPLIANCE SCORES':          'درجات الامتثال للوكلاء',
  'POLICY CHECK RESULTS BY AGENT':    'نتائج الفحص حسب الوكيل',
  'SYSTEM INVENTORY':                 'جرد النظام',
  'TOP 5 PLATFORMS':                  'أعلى 5 منصات',
  'TOP 5 OPERATING SYSTEMS':          'أعلى 5 أنظمة تشغيل',
  'ARCHITECTURE':                     'البنية المعمارية',
  'PACKAGES LIST':                    'قائمة الحزم',
  'TOP 5 VENDORS':                    'أعلى 5 موردين',
  'UNIQUE PACKAGES':                  'الحزم الفريدة',
  'PACKAGE TYPES':                    'أنواع الحزم',
  'PROCESS LIST':                     'قائمة العمليات',
  'TOP 5 PROCESSES':                  'أعلى 5 عمليات',
  'PROCESSES START TIME':             'وقت بدء العمليات',
  'USERS LIST':                       'قائمة المستخدمين',
  'TOP 5 USERS':                      'أعلى 5 مستخدمين',
  'TOP 5 USER GROUPS':                'أعلى 5 مجموعات مستخدمين',
  'TOP 5 USER SHELLS':                'أعلى 5 صدفات مستخدمين',
  'CLOUD EVENTS':                     'أحداث السحابة',
  'CONFIGURATION':                    'التكوين',
  'MANAGER API':                      'API المدير',
  'INDEXER API':                      'API المفهرس',
  'INDEX PATTERNS':                   'أنماط الفهارس',
  'MANAGER CONNECTION':               'اتصال المدير',
  'INDEXER CONNECTION':               'اتصال المفهرس',
  'CONFIGURED ENDPOINTS':             'نقاط النهاية المُكوَّنة',
  'GENERATE REPORT':                  'إنشاء تقرير',
  'SCHEDULED REPORTS':                'التقارير المجدولة',
  'EMAIL CONFIGURATION':              'تكوين البريد الإلكتروني',
  'SLACK CONFIGURATION':              'تكوين Slack',
  'ALERT RULES':                      'قواعد التنبيه',
  'MONITORED ENTITIES':               'الكيانات المراقَبة',
  'ANOMALIES · 7D':                   'الشذوذات · 7 أيام',
  'HIGH-RISK ENTITIES':               'الكيانات عالية الخطورة',
  'BASELINES HEALTHY':                'الخطوط الأساسية سليمة',
  'MONITORED ENTITIES':               'الكيانات المراقَبة',
  'ACTIVE NOTABLES':                  'الأحداث البارزة النشطة',
  'HIGHEST RISK SCORE':               'أعلى درجة مخاطر',
  'DEFAULT THRESHOLD':                'الحد الافتراضي',
  'TECHNIQUES DETECTED':              'التقنيات المكتشفة',
  'TACTICS COVERED':                  'التكتيكات المغطاة',
  'TOTAL MITRE ALERTS':               'إجمالي تنبيهات MITRE',
  'CRITICAL TECHNIQUES':              'التقنيات الحرجة',

  /* ── KPI subtexts ──────────────────────────────────────────────────── */
  'across the fleet · 30 d':          'عبر الأسطول · 30 يومًا',
  'no critical CVEs':                 'لا ثغرات حرجة',
  'no data':                          'لا بيانات',
  'all clear':                        'كل شيء طبيعي',
  'baseline':                         'الخط الأساسي',
  'total · last 24 h':                'المجموع · آخر 24 ساعة',
  'all time':                         'جميع الأوقات',
  'requires attention':               'يستدعي الانتباه',
  'in progress':                      'قيد التنفيذ',
  'closed out':                       'مُغلَق',
  'all models stable':                'جميع النماذج مستقرة',
  'risk score ≥ threshold':           'درجة المخاطر ≥ الحد',
  'auto-discovered':                  'اكتُشف تلقائيًا',
  'over threshold (100)':             'تجاوز الحد (100)',
  'below threshold':                  'تحت الحد',
  'highest score':                    'أعلى درجة',
  'configurable per-entity':          'قابل للتكوين لكل كيان',
  'unique T-IDs · 24h':              'معرفات T فريدة · 24 ساعة',
  'no detections':                    'لا اكتشافات',
  'of ATT&CK enterprise':            'من ATT&CK المؤسسي',
  'mapped to T-IDs · 24h':           'مرتبط بمعرفات T · 24 ساعة',
  'count ≥ 5 detections':            'العدد ≥ 5 اكتشافات',
  'Changes 24h':                     'التغييرات · 24 ساعة',
  'Files Added':                     'الملفات المضافة',
  'Files Modified':                  'الملفات المعدَّلة',
  'Files Deleted':                   'الملفات المحذوفة',
  'all actions':                     'جميع الإجراءات',
  'created':                         'أُنشئ',
  'content changed':                 'تغيَّر المحتوى',
  'removed':                         'أُزيل',
  'Auth Events 24h':                 'أحداث المصادقة · 24 ساعة',
  'Failed Logins':                   'تسجيلات الدخول الفاشلة',
  'Successful Logins':               'تسجيلات الدخول الناجحة',
  'Sudo Events':                     'أحداث Sudo',
  'all auth events':                 'جميع أحداث المصادقة',
  'authentication errors':           'أخطاء المصادقة',
  'authenticated sessions':          'جلسات مصادقة',
  'privilege escalation':            'تصعيد الصلاحيات',
  'Total Checks':                    'إجمالي الفحوصات',
  'Passed':                          'اجتاز',
  'Failed':                          'فشل',
  'Compliance Score':                'درجة الامتثال',
  'across all policies':             'عبر جميع السياسات',
  'compliant':                       'ممتثل',
  'needs remediation':               'يحتاج إصلاحًا',
  'fleet average':                   'متوسط الأسطول',
  'Total Users':                     'إجمالي المستخدمين',
  'Enabled':                         'مفعَّل',
  'Disabled':                        'معطَّل',
  'LDAP Synced':                     'مزامَن مع LDAP',
  'identities tracked':              'هويات مُتتبَّعة',
  'active accounts':                 'حسابات نشطة',
  'inactive accounts':               'حسابات غير نشطة',
  'from directory':                  'من الدليل',
  'Total Cases':                     'إجمالي الحالات',
  'Open':                            'مفتوح',
  'Investigating':                   'تحت التحقيق',
  'Resolved':                        'محلول',
  'all time':                        'جميع الأوقات',

  /* ── Report form ───────────────────────────────────────────────────── */
  'Report Period':                   'فترة التقرير',
  'Daily — Last 24 hours':           'يومي — آخر 24 ساعة',
  'Weekly — Last 7 days':            'أسبوعي — آخر 7 أيام',
  'Monthly — Last 30 days':          'شهري — آخر 30 يومًا',
  'Quarterly — Last 90 days':        'ربع سنوي — آخر 90 يومًا',
  'Format':                          'التنسيق',
  'PDF (download)':                  'PDF (تنزيل)',
  'HTML (browser)':                  'HTML (المتصفح)',
  'Generate Report':                 'إنشاء تقرير',

  /* ── Notifications ─────────────────────────────────────────────────── */
  'Send Test':                       'إرسال اختبار',

  /* ── Empty states ──────────────────────────────────────────────────── */
  'No events found':                 'لم يُعثر على أحداث',
  'No alerts found':                 'لم يُعثر على تنبيهات',
  'No vulnerabilities found':        'لم يُعثر على ثغرات',
  'No cases found':                  'لم يُعثر على حالات',
  'No playbooks yet':                'لا توجد دفاتر تشغيل بعد',
  'No tickets created yet':          'لم يتم إنشاء تذاكر بعد',
  'No inventory data yet':           'لا توجد بيانات جرد بعد',
  'No anomalies detected':           'لم يُكتشف أي شذوذ',
  'No active risk notables':         'لا توجد أحداث مخاطر نشطة',
  'No FIM events found':             'لم يُعثر على أحداث FIM',
  'No authentication events found':  'لم يُعثر على أحداث مصادقة',
  'No SCA results found':            'لم يُعثر على نتائج SCA',
  'No decoders found':               'لم يُعثر على فكّ ترميز',
  'No rules found':                  'لم يُعثر على قواعد',
  'No indexes found':                'لم يُعثر على فهارس',
  'No matching users':               'لم يُعثر على مستخدمين مطابقين',
  'No users found':                  'لم يُعثر على مستخدمين',
  'No cloud events found':           'لم يُعثر على أحداث سحابية',
  'No package data':                 'لا توجد بيانات حزم',
  'No process data':                 'لا توجد بيانات عمليات',
  'No identity data':                'لا توجد بيانات هوية',
  'No platform data':                'لا توجد بيانات منصة',
  'No OS data':                      'لا توجد بيانات نظام تشغيل',
  'No architecture data':            'لا توجد بيانات بنية معمارية',
  'No geo data yet':                 'لا توجد بيانات جغرافية بعد',
  'No MITRE ATT&CK data yet':        'لا توجد بيانات MITRE ATT&CK بعد',

  /* ── Pagination ────────────────────────────────────────────────────── */
  'Next →':     'التالي →',
  '← Prev':    '→ السابق',
  'Next':       'التالي',
  'Prev':       'السابق',
  'Page 1':     'الصفحة 1',
  '10 / page':  '10 / صفحة',
  '25 / page':  '25 / صفحة',
  '50 / page':  '50 / صفحة',

  /* ── Time range options ────────────────────────────────────────────── */
  'Last 15m':       'آخر 15 دقيقة',
  'Last 1h':        'آخر ساعة',
  'Last 24h':       'آخر 24 ساعة',
  'Last 7d':        'آخر 7 أيام',
  'Last 30d':       'آخر 30 يومًا',
  'Last 24 hours':  'آخر 24 ساعة',
  'Last 7 days':    'آخر 7 أيام',
  'Last 30 days':   'آخر 30 يومًا',
  'Last 7 days':    'آخر 7 أيام',
  'Last 30 days':   'آخر 30 يومًا',
  'Last 90 days':   'آخر 90 يومًا',
  'Last 1 hour':    'آخر ساعة',
  'Last 7 days':    'آخر 7 أيام',

  /* ── Login page ────────────────────────────────────────────────────── */
  'Sign in to Sentinel': 'تسجيل الدخول إلى Sentinel',
  'Username':            'اسم المستخدم',
  'Password':            'كلمة المرور',
  'Sign In':             'تسجيل الدخول',
};

/* ─────────────────────────────────────────────────────────────────────────
   Translation Engine
   ─────────────────────────────────────────────────────────────────────── */

let _currentLang = localStorage.getItem('sentinel_lang') || 'en';
const _backupNodes = new Map(); // WeakMap-style backup: node → original text

/* Elements whose text content must NOT be translated (live data) */
const _skipSelectors = [
  '#kpiTotalEvents', '#criticalCount', '#kpiMonitoredAssets', '#kpiOpenCases',
  '#kpiUebaAnomalies', '#kpiRbaNotables', '#tb2Clock', '#tb2PageName',
  '#agentsKpiTotal', '#agentsKpiActive', '#agentsKpiDisconnected', '#agentsKpiPending',
  '#agentsHealthPct', '#agentsUpdated', '#agentCardsGrid', '#agentsBody',
  '#discoverResultsWrap', '#casesTableBody', '#playbooksTableBody',
  '#executionsTableBody', '#ticketsTableBody', '#identityTableBody',
  '#cloudEventsBody', '#vulnBody', '#rulesBody', '#decodersBody',
  '#indexMgmtBody', '#fimEventsBody', '#auditEventsBody', '#scaAgentBody',
  '#complianceControlsBody', '#complianceScoreCards',
  '.discover-detail-table', '#rvFileList', '#rvVersionPane', '#rvEditorContent',
  'pre', 'code', 'kbd', '.tbl-mono[id]', '.ov2-feed', '#ovCasesList',
  '#ovUebaList', '#ovRbaList', '.kpi-value', '.ag2-stat-val', '.ov2-kpi-value',
].join(', ');

function _isLiveData(node) {
  try {
    if (!node.parentElement) return false;
    return !!node.parentElement.closest(_skipSelectors) ||
           node.parentElement.tagName === 'SVG' ||
           node.parentElement.closest('svg') ||
           node.parentElement.tagName === 'CODE' ||
           node.parentElement.tagName === 'PRE' ||
           node.parentElement.tagName === 'KBD';
  } catch { return false; }
}

function _allTextNodes(root) {
  const result = [];
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: n => (n.nodeValue.trim().length > 0) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP
  });
  while (walker.nextNode()) result.push(walker.currentNode);
  return result;
}

function _translateNode(tn, dict) {
  if (_isLiveData(tn)) return;
  const orig = _backupNodes.has(tn) ? _backupNodes.get(tn) : tn.nodeValue;
  if (!_backupNodes.has(tn)) _backupNodes.set(tn, orig);
  const trimmed = orig.trim();
  if (dict[trimmed]) {
    tn.nodeValue = tn.nodeValue.replace(trimmed, dict[trimmed]);
  }
}

function _restoreNode(tn) {
  if (_backupNodes.has(tn)) tn.nodeValue = _backupNodes.get(tn);
}

function _translateAttr(el, attr, dict) {
  const orig = el.getAttribute(`data-orig-${attr}`) || el[attr];
  if (!el.getAttribute(`data-orig-${attr}`)) el.setAttribute(`data-orig-${attr}`, orig || '');
  if (orig && dict[orig.trim()]) el[attr] = dict[orig.trim()];
}

function _restoreAttr(el, attr) {
  const orig = el.getAttribute(`data-orig-${attr}`);
  if (orig !== null) el[attr] = orig;
}

function applyLanguage(lang) {
  _currentLang = lang;
  localStorage.setItem('sentinel_lang', lang);

  const root  = document.documentElement;
  const body  = document.body;
  const btn   = document.getElementById('langToggleBtn');

  if (lang === 'ar') {
    root.setAttribute('dir', 'rtl');
    root.setAttribute('lang', 'ar');
    body.classList.add('lang-ar');

    // Translate ALL text nodes in the document except live data containers
    _allTextNodes(document.body).forEach(tn => _translateNode(tn, I18N_AR));

    // Translate placeholders and titles on inputs/buttons/selects
    document.querySelectorAll('input[placeholder], textarea[placeholder]').forEach(el => {
      _translateAttr(el, 'placeholder', I18N_AR);
    });
    document.querySelectorAll('[title]').forEach(el => {
      _translateAttr(el, 'title', I18N_AR);
    });

    if (btn) { btn.textContent = 'EN'; btn.title = 'Switch to English'; }

  } else {
    root.setAttribute('dir', 'ltr');
    root.setAttribute('lang', 'en');
    body.classList.remove('lang-ar');

    // Restore all text nodes
    _backupNodes.forEach((orig, tn) => { try { tn.nodeValue = orig; } catch {} });

    // Restore attributes
    document.querySelectorAll('[data-orig-placeholder]').forEach(el => _restoreAttr(el, 'placeholder'));
    document.querySelectorAll('[data-orig-title]').forEach(el => _restoreAttr(el, 'title'));

    if (btn) { btn.textContent = 'ع'; btn.title = 'Switch to Arabic / التبديل إلى العربية'; }
  }
}

function toggleLanguage() {
  applyLanguage(_currentLang === 'en' ? 'ar' : 'en');
}

// Re-translate dynamically rendered content (called when a page loads)
function i18nRefresh() {
  if (_currentLang === 'ar') {
    _allTextNodes(document.body).forEach(tn => _translateNode(tn, I18N_AR));
  }
}

// Auto-apply saved language after page load
document.addEventListener('DOMContentLoaded', () => {
  if (_currentLang === 'ar') applyLanguage('ar');
});
