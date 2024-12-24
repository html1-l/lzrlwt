class App {
    constructor() {
        // 修改消息数组为静态属性，使所有实例共享
        if (!App.messages) {
            App.messages = [];
        }
        this.messages = App.messages;

        // 添加题目数据
        this.quizData = {
            1: [ // 第一章题目
                {
                    question: "网络安全的基本目标不包括以下哪项？",
                    options: [
                        "A. 保密性",
                        "B. 完整性",
                        "C. 可用性",
                        "D. 经济性"
                    ],
                    answer: "D",
                    explanation: "网络安全的基本目标包括：保密性（Confidentiality）、完整性（Integrity）、可用性（Availability）和不可否认性（Non-repudiation）。经济性虽然重要，但不是网络安全的基本目标。"
                },
                {
                    question: "以下哪项不是网络安全的主要威胁？",
                    options: [
                        "A. 病毒攻击",
                        "B. 数据泄露",
                        "C. 系统升级",
                        "D. 未授权访问"
                    ],
                    answer: "C",
                    explanation: "系统升级是提高系统安全性的措施，而不是安全威胁。其他选项都是典型的网络安全威胁。"
                },
                {
                    question: "关于网络安全基础知识，以下说法错误的是？",
                    options: [
                        "A. 防火墙可以阻止所有类型的攻击",
                        "B. 加密可以保护数据安全",
                        "C. 密码应该定期更换",
                        "D. 备份是数据保护的重要手段"
                    ],
                    answer: "A",
                    explanation: "防火墙虽然是重要的安全设备，但不能阻止所有类型的攻击。需要配合其他安全措施才能提供全面的保护。"
                }
            ],
            2: [ // 第二章题目：黑客原理与防范措施
                {
                    question: "黑客攻击的主要目的不包括以下哪项？",
                    options: [
                        "A. 窃取信息",
                        "B. 破坏系统",
                        "C. 系统维护",
                        "D. 获取控制权"
                    ],
                    answer: "C",
                    explanation: "黑客攻击的主要目的包括窃取信息、破坏系统、获取控制权等恶意行为，而系统维护是系统管理员的正常工作，不是黑客攻击的目的。"
                },
                {
                    question: "以下哪种不是常见的黑客攻击手段？",
                    options: [
                        "A. 口令猜测",
                        "B. 系统漏洞利用",
                        "C. 定期备份",
                        "D. 木马程序"
                    ],
                    answer: "C",
                    explanation: "定期备份是系统安全防护措施，而不是攻击手段。其他选项都是常见的黑客攻击手段。"
                },
                {
                    question: "关于黑客攻击的特点，以下说法错误的是？",
                    options: [
                        "A. 攻击手段不断更新",
                        "B. 攻击目标具有针对性",
                        "C. 攻击总是能被防火墙检测到",
                        "D. 攻击可能造成严重损失"
                    ],
                    answer: "C",
                    explanation: "并非所有攻击都能被防火墙检测到，有些高级攻击手段可以绕过防火墙，或者利用合法流量进行攻击。"
                },
                {
                    question: "以下哪个不是有效的黑客防范措施？",
                    options: [
                        "A. 及时更新系统补丁",
                        "B. 配置防火墙规则",
                        "C. 从不修改密码",
                        "D. 安装防病毒软件"
                    ],
                    answer: "C",
                    explanation: "定期修改密码是基本的安全措施，从不修改密码会增加账户被攻破的风险。其他选项都是有效的防范措施。"
                },
                {
                    question: "关于系统漏洞，下列说法正确的是？",
                    options: [
                        "A. 系统漏洞无法修复",
                        "B. 只有Windows系统存在漏洞",
                        "C. 定期打补丁可以修复已知漏洞",
                        "D. 漏洞只会影响系统性能"
                    ],
                    answer: "C",
                    explanation: "通过及时安装系统补丁可以修复已知的安全漏洞。所有操作系统都可能存在漏洞，漏洞可能会带来安全风险，及时修复很重要。"
                },
                {
                    question: "以下哪种工具不属于黑客常用的扫描工具？",
                    options: [
                        "A. Nmap",
                        "B. Wireshark",
                        "C. Word",
                        "D. Nessus"
                    ],
                    answer: "C",
                    explanation: "Nmap是网络扫描工具，Wireshark是网络抓包工具，Nessus是漏洞扫描工具，而Word是文字处理软件，不是黑客工具。"
                },
                {
                    question: "关于社会工程学攻击，下列说法错误的是？",
                    options: [
                        "A. 利用人的心理弱点",
                        "B. 只能通过电子邮件进行",
                        "C. 可能造成信息泄露",
                        "D. 需要提高用户安全意识"
                    ],
                    answer: "B",
                    explanation: "社会工程学攻击不仅限于电子邮件，还包括电话诈骗、假冒身份、钓鱼网站等多种形式。"
                },
                {
                    question: "以下哪个不是DoS/DDoS攻击的特征？",
                    options: [
                        "A. 大量请求访问",
                        "B. 服务器资源耗尽",
                        "C. 正常用户无法访问",
                        "D. 服务器数据被窃取"
                    ],
                    answer: "D",
                    explanation: "DoS/DDoS攻击的主要目的是耗尽服务器资源，导致服务不可用，而不是窃取数据。数据窃取属于其他类型的攻击。"
                },
                {
                    question: "关于缓冲区溢出攻击，以下说法正确的是？",
                    options: [
                        "A. 只影响Linux系统",
                        "B. 可能导致程序崩溃或执行恶意代码",
                        "C. 无法通过代码计发现",
                        "D. 不需要进行漏洞修补"
                    ],
                    answer: "B",
                    explanation: "缓冲区溢出可能导致程序崩溃，严重时可能被利用执行恶意代码。这种漏洞可以通过代码审计发现，需要及时修补，且影响所有操作系统。"
                },
                {
                    question: "以下哪项不是预防SQL注入攻击的有效措施？",
                    options: [
                        "A. 参数化查询",
                        "B. 输入验证",
                        "C. 关闭错误提示",
                        "D. 使用明文密码"
                    ],
                    answer: "D",
                    explanation: "使用明文密码是严重的安全隐患。预防SQL注入应该使用参数化查询、进行输入验证、限制错误信息显示等措施。"
                }
            ],
            3: [ // 第三章题目：网络病毒防治
                {
                    question: "计算机病毒的基本特征不包括以下哪项？",
                    options: [
                        "A. 传染性",
                        "B. 潜伏性",
                        "C. 可视性",
                        "D. 破坏性"
                    ],
                    answer: "C",
                    explanation: "计算机病毒的基本特征包括传染性（能够自我复制和传播）、潜伏性（能够隐藏自己）、触发性（在特定条件下激活）和破坏性（对系统造成危害），而可视性不是病毒的特征。"
                },
                {
                    question: "下列哪种不是病毒的传播方式？",
                    options: [
                        "A. 通过U盘传播",
                        "B. 通过电子邮件传播",
                        "C. 通过系统升级传播",
                        "D. 通过网络共享传播"
                    ],
                    answer: "C",
                    explanation: "系统升级是官方提供的安全更新，不是病毒传播途径。病毒主要通过可移动存储设备、电子邮件附件、网络共享等方式传播。"
                },
                {
                    question: "以下哪个不是常见的病毒类型？",
                    options: [
                        "A. 蠕虫病毒",
                        "B. 木马病毒",
                        "C. 防火墙",
                        "D. 宏病毒"
                    ],
                    answer: "C",
                    explanation: "防火墙是网络安全防护工具，不是病毒类型。常见的病毒类型包括蠕虫病毒、木马病毒、宏病毒、引导型病毒等。"
                },
                {
                    question: "关于病毒防治，以下说法正确的是？",
                    options: [
                        "A. 安装杀毒软件后就不用更新了",
                        "B. 定期更新病毒库和系统补丁",
                        "C. 可以随意打开来源不明的附件",
                        "D. 不需要备份重要数据"
                    ],
                    answer: "B",
                    explanation: "定期更新病毒库和系统补丁是有效预防病毒的重要措施。其他选项都是错误的做法，会增加感染病毒的风险。"
                },
                {
                    question: "下列哪项不是病毒可能造成的危害？",
                    options: [
                        "A. 删除或篡改文件",
                        "B. 系统性能下降",
                        "C. 自动安装安全补丁",
                        "D. 窃取用户信息"
                    ],
                    answer: "C",
                    explanation: "自动安装安全补丁是系统安全功能，不是病毒危害。病毒通常会删除文件、降低系统性能、窃取信息等。"
                },
                {
                    question: "以下哪种行为最容易感染病毒？",
                    options: [
                        "A. 使用正版软件",
                        "B. 定期更新系统",
                        "C. 下载未知来源的软件",
                        "D. 安装杀毒软件"
                    ],
                    answer: "C",
                    explanation: "下载和安装未知来源的软件是最容易感染病毒的行为，应该避免。应该使用正版软件，保持系统更新，安装可靠的杀毒软件。"
                },
                {
                    question: "关于蠕虫病毒，以下说法错误的是？",
                    options: [
                        "A. 能够自我复制和传播",
                        "B. 需要依附其他程序",
                        "C. 可以通过网络传播",
                        "D. 会占用系统资源"
                    ],
                    answer: "B",
                    explanation: "蠕虫病毒的特点是能够独立存在和传播，不需要依附其他程序，这是它与普通病毒的主要区别。它能自我复制并通过网络传播，会占用系统资源。"
                },
                {
                    question: "以下哪种不是木马病毒的主要特征？",
                    options: [
                        "A. 隐蔽性",
                        "B. 远程控制",
                        "C. 自我复制",
                        "D. 信息窃取"
                    ],
                    answer: "C",
                    explanation: "木马病毒通常不具有自我复制能力，这是它与病毒和蠕虫的主要区别。木马的主要特征是隐蔽性强、具有远程控制功能、可以窃取信息。"
                },
                {
                    question: "杀毒软件的主要功能不包括？",
                    options: [
                        "A. 病毒查杀",
                        "B. 系统加速",
                        "C. 实时防护",
                        "D. 病毒库更新"
                    ],
                    answer: "B",
                    explanation: "系统加速不是杀毒软件的主要功能。杀毒软件的核心功能包括病毒查杀、实时防护、病毒库更新等安全防护功能。"
                },
                {
                    question: "关于病毒特征码，以下说法正确的是？",
                    options: [
                        "A. 所有病毒都有固定的特征码",
                        "B. 特征码永远不会改变",
                        "C. 变种病毒可能有不同特征码",
                        "D. 不需要更新病毒特征库"
                    ],
                    answer: "C",
                    explanation: "病毒可能产生变种，导致特征码发生变化，这就是为什么需要经常更新病毒库。不是所有病毒都有固定特征码，特征码也不是永远不变的。"
                },
                {
                    question: "预防计算机病毒感染的最佳实践不包括？",
                    options: [
                        "A. 安装防病毒软件",
                        "B. 从不备份数据",
                        "C. 及时更新系统补丁",
                        "D. 不打开可疑附件"
                    ],
                    answer: "B",
                    explanation: "定期备份数据是预防病毒感染的重要措施，可以在系统受感染时恢复数据。其他选项都是正确的预防措施。"
                },
                {
                    question: "关于病毒清除，下列说法错误的是？",
                    options: [
                        "A. 所有病毒都能被杀毒软件清除",
                        "B. 有些病毒需要专门的清除工具",
                        "C. 清除后应该重新扫描确认",
                        "D. 有些情况需要重装系统"
                    ],
                    answer: "A",
                    explanation: "并非所有病毒都能被杀毒软件清除，有些复杂的病毒可能需要专门的清除工具，严重时甚至需要重装系统���清除后重新扫描是必要的确认步骤。"
                }
            ],
            4: [ // 第四章题目密码技术
                {
                    question: "以下哪个不是密码技术的基本功能？",
                    options: [
                        "A. 保密性",
                        "B. 完整性",
                        "C. 可读性",
                        "D. 认证性"
                    ],
                    answer: "C",
                    explanation: "密码技术的基本功能包括保密性（保密）、完整性（数字签名）、认证性（身份验证）和不可否认性，可读性不是密码技术的基本功能。"
                },
                {
                    question: "关于对称密码与非对称密码，下列说法正确的是？",
                    options: [
                        "A. 对称密码加密速度慢",
                        "B. 非对称密码密钥分发简单",
                        "C. 对称密码使用相同的密钥加解密",
                        "D. 非对称密码抗攻击能力弱"
                    ],
                    answer: "C",
                    explanation: "对称密码使用相同的密钥进行加密和解密。对称密码加密速度快，但密钥分发复杂；非对称密码加密速度慢，但密钥分发简单，抗攻击能力强。"
                },
                {
                    question: "以下哪个不是常见的加密算法？",
                    options: [
                        "A. DES",
                        "B. AES",
                        "C. HTTP",
                        "D. RSA"
                    ],
                    answer: "C",
                    explanation: "DES和AES是对称加密算法，RSA是非对称加密算法，而HTTP是超文本传输协议，不是加密算法。"
                },
                {
                    question: "数字签名的主要作用不包括？",
                    options: [
                        "A. 身份认证",
                        "B. 数据加密",
                        "C. 完整性检查",
                        "D. 不可否认性"
                    ],
                    answer: "B",
                    explanation: "数字签名主要用于身份认证、完整性检查和不可否认性，而不是用于数据加密。数据加密通常使用其他加密算法实现。"
                },
                {
                    question: "关于密钥管理，以下说法错误的是？",
                    options: [
                        "A. 密钥需要定期更换",
                        "B. 密钥可以重复使用",
                        "C. 密钥需要安全存储",
                        "D. 密钥长度影响安全性"
                    ],
                    answer: "B",
                    explanation: "密钥不应重复使用，这会降低系统安全性。密钥应该定期更换、安全存储，并且密钥长度确实会影响加密强度。"
                },
                {
                    question: "SSL/TLS协议的主要功能不包括？",
                    options: [
                        "A. 数据加密",
                        "B. 身份认证",
                        "C. 文件压缩",
                        "D. 密钥交换"
                    ],
                    answer: "C",
                    explanation: "SSL/TLS协议主要提供数据加密、身份认证和密钥交换功能，确保网络通信安全。文件压缩不是SSL/TLS的主要功能。"
                },
                {
                    question: "关于哈希函数，以下说法错误的是？",
                    options: [
                        "A. 输出长度固定",
                        "B. 可以还原原始数据",
                        "C. 抗碰撞性",
                        "D. 单向性"
                    ],
                    answer: "B",
                    explanation: "哈希函数是单向函数，不能从哈希值还原原始数据。它具有固定输出长度、抗碰撞性（很难找到具有相同哈希值的不同输入）和单向性等特征。"
                },
                {
                    question: "以下哪个不是常见的哈希算法？",
                    options: [
                        "A. MD5",
                        "B. SHA-1",
                        "C. AES-256",
                        "D. SHA-256"
                    ],
                    answer: "C",
                    explanation: "AES-256是对称加密算法，不是哈希算法。MD5、SHA-1和SHA-256都是常见的哈希算法，用于生成消息摘要。"
                },
                {
                    question: "PKI（公钥基础设施）的主要组成部分不包括？",
                    options: [
                        "A. 证书颁发机构（CA）",
                        "B. 数字证书",
                        "C. 病毒扫描器",
                        "D. 证书撤销列表（CRL）"
                    ],
                    answer: "C",
                    explanation: "病毒扫描器不是PKI的组成部分。PKI主要包括CA、数字证书、证书撤销列表、密钥对等组件，用于管理和分发公钥。"
                },
                {
                    question: "关于数字证书，以下说法正确的是？",
                    options: [
                        "A. 永远不会过期",
                        "B. 只能用于网站认证",
                        "C. 包含持有者的公钥信息",
                        "D. 不需要CA签名"
                    ],
                    answer: "C",
                    explanation: "数字证书包含持有者的公钥、身份信息等，并由CA签名。证书有有效期限，可用于网站认证、邮件加密等多种场景。"
                },
                {
                    question: "以下哪种场景不适合使用对称加密？",
                    options: [
                        "A. 本地文件加密",
                        "B. 网上银行交易",
                        "C. 大文件加密",
                        "D. 内部网络通信"
                    ],
                    answer: "B",
                    explanation: "网上银行交易需要安全的密钥交换，适合使用非对称加密。对称加密适合本地文件加密、大文件加密和可以安全交换密钥的内部网络通信。"
                },
                {
                    question: "PGP（Pretty Good Privacy）主要用于？",
                    options: [
                        "A. 网站认证",
                        "B. 电子邮件加密",
                        "C. 网络监控",
                        "D. 入侵检测"
                    ],
                    answer: "B",
                    explanation: "PGP主要用于电子邮件的加密和数字签名，提供端到端的安全通信。它结合了对称加密、非对称加密和数字签名等技术。"
                }
            ],
            5: [ // 第五章题目：防火墙技术
                {
                    question: "防火墙的主要功能不包括以下哪项？",
                    options: [
                        "A. 访问控制",
                        "B. 数据过滤",
                        "C. 系统备份",
                        "D. 日志记录"
                    ],
                    answer: "C",
                    explanation: "防火墙的主要功能包括访问控制、数据过滤、日志记录和安全审计等，系统备份不是防火墙的主要功能。"
                },
                {
                    question: "以下哪个不是防火墙的工作原理？",
                    options: [
                        "A. 包过滤",
                        "B. 应用代理",
                        "C. 系统重装",
                        "D. 状态检测"
                    ],
                    answer: "C",
                    explanation: "防火墙的主要工作原理包括包过滤、应用代理、状态检测等，系统重装是系统维护操作，不是防火墙的工作原理。"
                },
                {
                    question: "关于包过滤防火墙，以下说法错误的是？",
                    options: [
                        "A. 基于TCP/IP协议",
                        "B. 可以过滤IP地址",
                        "C. 可以分析应用层内容",
                        "D. 处理速度快"
                    ],
                    answer: "C",
                    explanation: "包过滤防火墙主要工作在网络层和传输层，不能分析应用层内容。它可以过滤IP地址和端口，处理速度快，是基于TCP/IP协议的。"
                },
                {
                    question: "以下哪个不是防火墙的部署方式？",
                    options: [
                        "A. 双向防火墙",
                        "B. 三向防火墙",
                        "C. 无防火墙",
                        "D. 分布式防火墙"
                    ],
                    answer: "C",
                    explanation: "无防火墙不是一种部署方式，这会导致网络完全暴露在威胁中。常见的部署方式包括单防火墙、双向防火墙和分布式防火墙等。"
                },
                {
                    question: "关于应用网关防火墙，以下说法正确的是？",
                    options: [
                        "A. 处理速度比包过滤快",
                        "B. 不能提供用户认证",
                        "C. 可以详细检查应用层数据",
                        "D. 不需要额外的系统资源"
                    ],
                    answer: "C",
                    explanation: "应用网关防火墙可以详细检查应用层数据，提供更强的安全性，但处理速度较慢，需要较多系统资源，通常也提供用户认证功能。"
                },
                {
                    question: "防火墙日志记录的主要作用不包括？",
                    options: [
                        "A. 安全审计",
                        "B. 入侵检测",
                        "C. 系统加速",
                        "D. 故障排除"
                    ],
                    answer: "C",
                    explanation: "防火墙日志记录主要用于安全审计、入侵检测和故障排除，系统加速不是日志记录的功能。"
                },
                {
                    question: "关于状态检测防火墙，以下说法错误的是？",
                    options: [
                        "A. 可以记录连接状态",
                        "B. 比包过滤防火墙更安全",
                        "C. 不需要额外的系统资源",
                        "D. 能检测协议异常"
                    ],
                    answer: "C",
                    explanation: "状态检测防火墙需要额外的系统资源来维护连接状态表。它比简单的包过滤更安全，可以记录和跟踪连接状态，检测协议异常。"
                },
                {
                    question: "防火墙策略配置的最佳实践不包括？",
                    options: [
                        "A. 默认拒绝所有",
                        "B. 定期审查规则",
                        "C. 允许所有出站流量",
                        "D. 最小权限原则"
                    ],
                    answer: "C",
                    explanation: "允许所有出站流量不是最佳实践，应该基于最小权限原则配置出站规则。其他选项都是防火墙配置的最佳实践。"
                },
                {
                    question: "以下哪个端口不是常见的需要在防火墙上管控的服务端口？",
                    options: [
                        "A. HTTP(80)",
                        "B. SSH(22)",
                        "C. LOCAL(1024)",
                        "D. FTP(21)"
                    ],
                    answer: "C",
                    explanation: "1024是本地端口示例，不是标准服务端口。HTTP(80)、SSH(22)、FTP(21)都是常见的需要在防火墙上进行访问控制的服务端口。"
                },
                {
                    question: "关于DMZ（隔离区），以下说法正确的是？",
                    options: [
                        "A. 可以直接访问内网",
                        "B. 位于内外网之间",
                        "C. 不需要防火墙保护",
                        "D. 只允许外网访问"
                    ],
                    answer: "B",
                    explanation: "DMZ位于内网和外网之间，是一个缓冲区。它需要防火墙保护，不能直接访问内网，且需要严格控制访问权限。"
                },
                {
                    question: "以下哪项不是评估防火墙性能的指标？",
                    options: [
                        "A. 吞吐量",
                        "B. 并发连接数",
                        "C. 显示分辨率",
                        "D. 响应延迟"
                    ],
                    answer: "C",
                    explanation: "显示分辨率与防火墙性能无关。评估防火墙性能的主要指标包括吞吐量、并发连接数、响应延迟等网络性能参数。"
                },
                {
                    question: "NAT（网络地址转换）的主要作用不包括？",
                    options: [
                        "A. 节省公网IP",
                        "B. 提高安全性",
                        "C. 加密数据",
                        "D. 隐藏内网结构"
                    ],
                    answer: "C",
                    explanation: "NAT主要用于地址转换，可以节省公网IP、提高安全性和隐藏内网结构，但不具备数据加密功能。数据加密需要使用其他安全协议。"
                }
            ],
            6: [ // 第六章题目：Windows的安全与保护
                {
                    question: "Windows系统安全策略不包括以下哪项？",
                    options: [
                        "A. 密码策略",
                        "B. 审核策略",
                        "C. 游戏策略",
                        "D. 账户策略"
                    ],
                    answer: "C",
                    explanation: "Windows系统安全策略要包括密码策略、审核策略、账户策略等，游戏策略不属于系��安全策略范畴。"
                },
                {
                    question: "关于Windows用户账户管理，以下说法错误的是？",
                    options: [
                        "A. 应该使用最小权限原则",
                        "B. 管理员账户可随意共享",
                        "C. 需定期修改密码",
                        "D. 及时删除无用账户"
                    ],
                    answer: "B",
                    explanation: "管理员账户权限最高，应该严格保护，不能随意共享。应该遵循最小权限原则，定���修改密码，��时删除无用账户。"
                },
                {
                    question: "以下哪个不是Windows系统日志类型",
                    options: [
                        "A. 系统日志",
                        "B. 应用程序日志",
                        "C. 安全日志",
                        "D. 娱乐日志"
                    ],
                    answer: "D",
                    explanation: "Windows主要的日志类型包括系统日志、应用程序日志、安全日志等，不包括娱乐日志。日志对系统监控和故障排查很重要。"
                },
                {
                    question: "关于Windows文件系统安全，下列说法正确的是？",
                    options: [
                        "A. 共享文件夹默认对所有人开放",
                        "B. NTFS提供更细致的权限控制",
                        "C. FAT32NTFS更安全",
                        "D. 不需要设置文件访问权限"
                    ],
                    answer: "B",
                    explanation: "NTFS文件系统提供更细致的访问权限控制，比FAT32更安全。共享文件夹应该设置适当的访问权限，不应该默认对所有人开放���"
                },
                {
                    question: "Windows系统安全加固措施不包括？",
                    options: [
                        "A. 及时安装安全补丁",
                        "B. 配置防火墙规则",
                        "C. 安装正版游戏",
                        "D. 禁用不必要的服务"
                    ],
                    answer: "C",
                    explanation: "安装正版游戏不是系统安全加固措施。系统安全加固应该包括及时更新补���、配置防火墙、禁用不必要服务等。"
                },
                {
                    question: "关于Windows组策略，以下说法错误的是？",
                    options: [
                        "A. 可以集中管理系统设置",
                        "B. 只能在服务器上使用",
                        "C. 可以控制用户权限",
                        "D. 支持安全策略配置"
                    ],
                    answer: "B",
                    explanation: "组策略不仅可以在服务器上使���，也可以在专业版Windows系统中使用。它是一个强大的集中管理和安全配置工具。"
                },
                {
                    question: "Windows系统中，以下哪个不是提高密码安全性的有效措施？",
                    options: [
                        "A. 设置密码最短长度",
                        "B. 启用密码复杂度要求",
                        "C. 使用生日作为密码",
                        "D. 定期更换密码"
                    ],
                    answer: "C",
                    explanation: "使用生日作为密码容易被猜测，不安全。应该设置复杂的密码，包含大小写字母、数字和特殊字符，并定期更换。"
                },
                {
                    question: "关于Windows服务管理，以下说法正确的是？",
                    options: [
                        "A. 所有服务都应该启用",
                        "B. 禁用服务可能影响安全性",
                        "C. 应该根据需要配置服务",
                        "D. 服务配置不需要权限"
                    ],
                    answer: "C",
                    explanation: "应该根据实际需要配置服务，禁用不必要的服务可以减少攻击面。不是所有服务都需要启用，服务配置需要管理员权限。"
                },
                {
                    question: "Windows系统备份策略中，不推荐的做法是？",
                    options: [
                        "A. 定期进行系统备份",
                        "B. 将备份保存在同一硬盘",
                        "C. 测试备份的可用性",
                        "D. 加密重要备份文件"
                    ],
                    answer: "B",
                    explanation: "将备份保存在同一硬盘上有风险，如果硬盘损坏会导致数据和备份同时丢失。应该将备份保存在不同的物理位置。"
                },
                {
                    question: "以下哪个不是Windows事件查看器的主要用途？",
                    options: [
                        "A. 监控系统事件",
                        "B. 排查系统问题",
                        "C. 优化系统性能",
                        "D. 追踪安全事件"
                    ],
                    answer: "C",
                    explanation: "事件查看器主要用于监控系统事件、排查问题和追踪安全事件，系统性能优化主要使用性能监视器等其他工具。"
                },
                {
                    question: "关于Windows用户权限管理，以下做法错误的是？",
                    options: [
                        "A. 限制普通用户权限",
                        "B. 所有用户都使用管理员账户",
                        "C. 定期审查用户权限",
                        "D. 遵循最小权限原则"
                    ],
                    answer: "B",
                    explanation: "让所有用户都使用管理员账户是非常危险的做法。应该遵循最小权限原则，只给用户必要的权限，并定期审查。"
                },
                {
                    question: "Windows安全中心的功能不包括？",
                    options: [
                        "A. 防病毒软件状态",
                        "B. 游戏性能优化",
                        "C. 防火墙设置",
                        "D. 自动更新状态"
                    ],
                    answer: "B",
                    explanation: "Windows安全中心主要负责监控系统安全状态，包括防病毒、防火墙、更新等安全功能，不负责游戏性能优化。"
                }
            ],
            7: [ // 第七章题目：Web应用安全
                {
                    question: "以下哪个不是常见的Web应用安全威胁？",
                    options: [
                        "A. SQL注入",
                        "B. XSS攻击",
                        "C. 系统重启",
                        "D. CSRF攻击"
                    ],
                    answer: "C",
                    explanation: "系统重启是系统维护操作，不是Web安全威胁。SQL注入、XSS（跨站脚本）和CSRF（跨站请求伪造）都是常见的Web应用安全威胁。"
                },
                {
                    question: "关于SQL注入攻击，以下说法错误的是？",
                    options: [
                        "A. 可能导致数据泄露",
                        "B. 只影响Windows系统",
                        "C. 需要进行输入验证",
                        "D. 可能删除数据库"
                    ],
                    answer: "B",
                    explanation: "SQL注入攻击与操作系统无关，它是针对数据库的攻击。可能导致数据泄露、数据被删除等严重后果，需要通过输入验证等措施防范。"
                },
                {
                    question: "以下哪个不是预防XSS攻击的有效措施？",
                    options: [
                        "A. 过滤特殊字符",
                        "B. 使用HttpOnly Cookie",
                        "C. 禁用所有JavaScript",
                        "D. 输入数据验证"
                    ],
                    answer: "C",
                    explanation: "完全禁用JavaScript会影响网站功能，不是合适的XSS防护措施。应该通过过滤特殊字符、使用HttpOnly Cookie、验证输入数据等方式防范XSS攻击。"
                },
                {
                    question: "CSRF攻击的主要防护措施不包括？",
                    options: [
                        "A. 使用CSRF Token",
                        "B. 验证Referer",
                        "C. 存储明文密码",
                        "D. 使用SameSite Cookie"
                    ],
                    answer: "C",
                    explanation: "存储明文密码是严重的安全隐患，不是CSRF防护措施。有效的CSRF防护包括使用Token、验证Referer和设置SameSite Cookie等。"
                },
                {
                    question: "关于Web应用防火墙(WAF)，以下说法正确的是？",
                    options: [
                        "A. 可以防御所有攻击",
                        "B. 不需要更新规则",
                        "C. 可以过滤恶意请求",
                        "D. 完全替代代码安全"
                    ],
                    answer: "C",
                    explanation: "WAF可以过滤恶意请求，但不能防御所有攻击，需要定期更新规则，且不能完全替代代码层面的安全措施。"
                },
                {
                    question: "以下哪个不是安全的Session管理实践？",
                    options: [
                        "A. 定期轮换Session ID",
                        "B. 使用固定Session ID",
                        "C. 设置Session超时",
                        "D. 加密Session数据"
                    ],
                    answer: "B",
                    explanation: "使用固定Session ID是不安全的做法，容易被攻击者利用。应该定期轮换Session ID、设置合理的超时时间、加密Session数据。"
                },
                {
                    question: "关于文件上传漏洞，以下说法错误的是？",
                    options: [
                        "A. 需要验证文件类型",
                        "B. 可以执行任意文件",
                        "C. 不需要限制文件大小",
                        "D. 应该重命名文件"
                    ],
                    answer: "C",
                    explanation: "文件上传安全需要限制文件大小，防止服务器资源耗尽。同时要验证文件类型、重命名文件，防止恶意文件上传和执行。"
                },
                {
                    question: "以下哪个HTTP响应头不是用于安全防护的？",
                    options: [
                        "A. X-XSS-Protection",
                        "B. Content-Security-Policy",
                        "C. Content-Length",
                        "D. X-Frame-Options"
                    ],
                    answer: "C",
                    explanation: "Content-Length是用于指示响应体长度的标准头，不是安全相关的。其他都是用于Web安全防护的响应头，如XSS防护、内容安全策略、点击劫持防护等。"
                },
                {
                    question: "关于Cookie安全，以下最佳实践不包括？",
                    options: [
                        "A. 设置Secure标志",
                        "B. 使用HttpOnly",
                        "C. 存储明文密码",
                        "D. 设置SameSite"
                    ],
                    answer: "C",
                    explanation: "Cookie中存储明文密码是严重的安全隐患。应该设置Secure确保只通过HTTPS传输、使用HttpOnly防止XSS获取Cookie、设置SameSite防止CSRF攻击。"
                },
                {
                    question: "以下哪个不是Web应用安全测试的方法？",
                    options: [
                        "A. 漏洞扫描",
                        "B. 渗透测试",
                        "C. 系统重装",
                        "D. 代码审计"
                    ],
                    answer: "C",
                    explanation: "系统重装是系统维护操作，不是安全测试方法。Web应用安全测试包括漏洞扫描、渗透测试、代码审计等方法。"
                },
                {
                    question: "关于API安全，以下说法正确的是？",
                    options: [
                        "A. 不需要身份认证",
                        "B. 应该使用HTTPS",
                        "C. 可以暴露敏感信息",
                        "D. 无需访问控制"
                    ],
                    answer: "B",
                    explanation: "API应该使用HTTPS加密传输，同时需要实施身份认证、访问控制，避免暴露敏感信息。这些都是保护API安全的基本要求。"
                },
                {
                    question: "以下哪个不是安全的密码存储方式？",
                    options: [
                        "A. 使用加盐哈希",
                        "B. 明文存储",
                        "C. 使用bcrypt",
                        "D. 使用PBKDF2"
                    ],
                    answer: "B",
                    explanation: "明文存储密码是极其不安全的做法。应该使用加盐哈希、bcrypt或PBKDF2等安全的密码哈希算法来存储密码。"
                }
            ]
        };

        this.pages = {
            home: `
                <div class="animate__animated animate__fadeIn">
                    <!-- 网站宣传图 -->
                    </div>

                    <!-- 内容区域 -->
                    <div class="prose max-w-none">
                        <div class="bg-white rounded-lg shadow-lg p-8">
                            <h2 class="text-2xl font-bold mb-4 text-blue-800">一、背景与重要性</h2>
                            <p class="text-gray-700 mb-6 leading-relaxed">
                                随着互联网的飞速发展，计算机网络已经深入到社会的各个角落，如金融、医疗、交通、能源等关键领域。然而，网络安全威胁也日益复杂和多样化。例如，银行系统如果遭受网络攻击，可能会导致客户资金被盗取；医院的医疗信息系统被入侵，患者的隐私信息就会泄露。因此，保障计算机网络安全与个人隐私、企业利益乃至国家安全都具有极其重要的战略意义。
                            </p>

                            <h2 class="text-2xl font-bold mb-4 text-blue-800">二、主要威胁类型</h2>
                            <h3 class="text-xl font-semibold mb-3 text-blue-700">恶意软件（Malware）</h3>
                            <ul class="list-disc list-inside mb-4 text-gray-700 space-y-2">
                                <li><strong>病毒（Virus）：</strong>它是一种能够自我复制并感染其他程序的恶意代码。例如，CIH 病毒，它会破坏计算机的 BIOS 和硬盘数据，导致计算机无法正常启动。</li>
                                <li><strong>蠕虫（Worm）：</strong>蠕虫与病毒的区别在于它不需要依附于其他程序就能独立传播。比如，"红色代码" 蠕虫利用了微软 IIS 服务器的漏洞。</li>
                                <li><strong>木马（Trojan Horse）：</strong>木马程序通常伪装成正常的软件，诱使用户安装。例如，灰鸽子木马可以获取用户的账号密码、文件等信息。</li>
                            </ul>

                            <h3 class="text-xl font-semibold mb-3 text-blue-700">网络攻击（Network Attacks）</h3>
                            <ul class="list-disc list-inside mb-4 text-gray-700 space-y-2">
                                <li><strong>拒绝服务攻击（DoS/DDoS）：</strong>通过发送大量请求使服务器无法正常工作。</li>
                                <li><strong>中间人攻击：</strong>在通信双方之间拦截并篡改通信内容。</li>
                            </ul>

                            <h2 class="text-2xl font-bold mb-4 text-blue-800">三、主要安全技术分类</h2>
                            <div class="space-y-4">
                                <div>
                                    <h3 class="text-xl font-semibold mb-2 text-blue-700">防火墙技术（Firewall）</h3>
                                    <p class="text-gray-700 leading-relaxed">防火墙是位于内部网络和外部网络之间安全护系统，可以根据预设则控网络量。</p>
                                </div>
                                <div>
                                    <h3 class="text-xl font-semibold mb-2 text-blue-700">加密技术（Encryption）</h3>
                                    <p class="text-gray-700 leading-relaxed">通过将数据转换为密文来保护数据安全，如SSL/TLS协议、AES和RSA算法等。</p>
                                </div>
                                <div>
                                    <h3 class="text-xl font-semibold mb-2 text-blue-700">入侵检测与防御系统（IDS/IPS）</h3>
                                    <p class="text-gray-700 leading-relaxed">监测和防御网络中的异常活动和入侵行为。</p>
                                </div>
                            </div>

                            <h2 class="text-2xl font-bold mb-4 mt-6 text-blue-800">四、发展趋势</h2>
                            <p class="text-gray-700 leading-relaxed">
                                随着人工智能和机器学习技术的应用，安全系统变得更加智能化。物联网的发展带来新的挑战，量子计算的出现也促使加密技术不断革新。网络安全技术正在向更智能、更全面的方向发展。
                            </p>
                        </div>
                    </div>
                </div>
            `,
            courses: `
                <div class="prose max-w-none">
                    <h2 class="text-2xl font-bold mb-6 text-blue-800">课程内容</h2>
                    <div class="space-y-8">
                        <!-- 第一章 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第一章：网络安全概述</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>1.1 网络安全简介与涉及的内容</span>
                                    <button onclick="window.location.href='courses/ch1-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>1.2 网络安全防护体系</span>
                                    <button onclick="window.location.href='courses/ch1-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                            </ul>
                            <div class="mt-4 flex space-x-2">
 
                            </div>
                        </div>

                        <!-- 第二章 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第二章：黑客攻防技术</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>2.1 黑客概述及目标系统的探测(nmap)</span>
                                    <button onclick="window.location.href='courses/ch2-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.2 目标扫描（XSCAN)</span>
                                    <button onclick="window.location.href='courses/ch2-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.3 口令破解过程（smbcrack2)</span>
                                    <button onclick="window.location.href='courses/ch2-3.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.4 网络监听工具的使用（sniffer)</span>
                                    <button onclick="window.location.href='courses/ch2-4.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.5 木马的攻防（冰河木马)</span>
                                    <button onclick="window.location.href='courses/ch2-5.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.6 拒绝服务攻击（DDOS)</span>
                                    <button onclick="window.location.href='courses/ch2-6.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.7 ARP攻击的防范</span>
                                    <button onclick="window.location.href='courses/ch2-7.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>2.8 缓冲区溢出</span>
                                    <button onclick="window.location.href='courses/ch2-8.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">
                              
                                
                            </div>
                        </div>

                        <!-- 第三章：网络病毒防治 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第三章：网络病毒防治</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>3.1 病毒的基本概念及原类</span>
                                    <button onclick="window.location.href='courses/ch3-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>3.2 计算机感染典型病毒的现象</span>
                                    <button onclick="window.location.href='courses/ch3-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>3.3 常用的杀毒软件介绍</span>
                                    <button onclick="window.location.href='courses/ch3-3.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">
                               
                                
                            </div>
                        </div>

                        <!-- 第四章：密码技术 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第四章：密码技术</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>4.1 密码学的基本概念及数据加密技术在网络安全中的应用</span>
                                    <button onclick="window.location.href='courses/ch4-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>4.2 数据加密、传送及解密</span>
                                    <button onclick="window.location.href='courses/ch4-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">



                            </div>
                        </div>

                        <!-- 第五章：防火墙技术 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第五章：防火墙技术</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>5.1 防火墙的基本概念及掌握防火墙的操作基本原理</span>
                                    <button onclick="window.location.href='courses/ch5-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>5.2 第三方防火墙的应用</span>
                                    <button onclick="window.location.href='courses/ch5-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>5.3 VPN</span>
                                    <button onclick="window.location.href='courses/ch5-3.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">


                            </div>
                        </div>

                        <!-- 第六章：Windows的安全与保护机制 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第六章：Windows的安全与保护机制</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>6.1 Windows系统的安全机制并掌握Windows系统的常用全设置</span>
                                    <button onclick="window.location.href='courses/ch6-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>6.2 Windows Server的帐户管理</span>
                                    <button onclick="window.location.href='courses/ch6-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>6.3 Windows Server注册表与组策略</span>
                                    <button onclick="window.location.href='courses/ch6-3.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>6.4 Windows Server常用的系统进程和服务</span>
                                    <button onclick="window.location.href='courses/ch6-4.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>6.5 Windows server的日管理</span>
                                    <button onclick="window.location.href='courses/ch6-5.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">
                                
                                

                            </div>
                        </div>

                        <!-- 第七章：Web应用安全 -->
                        <div class="course-card bg-white p-6 rounded-lg shadow">
                            <h3 class="text-xl font-bold mb-3 text-blue-700">第七章：Web应用安全</h3>
                            <ul class="list-disc list-inside space-y-2 text-gray-700">
                                <li class="flex items-center justify-between">
                                    <span>7.1 Web安全概</span>
                                    <button onclick="window.location.href='courses/ch7-1.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>7.2 Web应用程序安全</span>
                                    <button onclick="window.location.href='courses/ch7-2.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>7.3 Web服务器软件的安全</span>
                                    <button onclick="window.location.href='courses/ch7-3.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                                <li class="flex items-center justify-between">
                                    <span>7.4 Web传输安全及SSL安全</span>
                                    <button onclick="window.location.href='courses/ch7-4.html'" class="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600">
                                        进入课程
                                    </button>
                                </li>
                            </ul>
                            <div class="mt-4 flex space-x-2">
                               

                            </div>
                        </div>
                    </div>

                    <!-- 管理员专属功能：添加新课程 -->
                    <div class="admin-only mt-8" style="display: none;">
                        <button class="upload-btn bg-green-500 text-white px-6 py-3 rounded-lg hover:bg-green-600">
                            <i class="fas fa-plus mr-2"></i>添加新课程
                        </button>
                    </div>
                </div>
            `,
            resources: `
                <div class="bg-white rounded-lg shadow-lg p-6">
                    <h2 class="text-2xl font-bold mb-6 text-blue-800 text-center">网络安全技术测试题库</h2>
                    <p class="text-gray-600 text-center mb-8">选择章节开始测试你的网络安全知识！</p>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <!-- 第一章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-shield-alt text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第一章：网络安全概述</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对网络安全基础概念的理解</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="1">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第二章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-user-secret text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第二章：黑客原理与防范措施</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对黑客攻击与防范的认识</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="2">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第三章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-virus-slash text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第三章：网络病毒防治</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对病毒防护的掌握程度</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="3">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第四章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-key text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第四章：密码技术</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对密码学知识的理解</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="4">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第五章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-fire-alt text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第五章：防火墙技术</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对防火墙原理的掌握</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="5">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第六章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fab fa-windows text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第六章：Windows的安全与保护</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对Windows安全机制的了解</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="6">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                        
                        <!-- 第七章 -->
                        <div class="quiz-card bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 border border-gray-100">
                            <div class="flex items-center mb-3">
                                <i class="fas fa-globe text-blue-500 text-xl mr-2"></i>
                                <h3 class="text-lg font-semibold text-blue-700">第七章：Web应用安全</h3>
                            </div>
                            <p class="text-gray-600 mb-4 text-sm">测试你对Web安全的认识</p>
                            <button class="start-quiz bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 w-full transform hover:-translate-y-1 transition-all duration-200" data-chapter="7">
                                <i class="fas fa-play-circle mr-2"></i>
                                开始测试
                            </button>
                        </div>
                    </div>
                    <!-- 题目容器 -->
                    <div id="questions-container" class="space-y-6 hidden">
                        <!-- 试题将通过JavaScript动态加载 -->
                        <div class="loading">正在加载试题...</div>
                    </div>
                </div>
            `,
            chat: `
                <div class="bg-white rounded-lg shadow-lg p-8">
                    <h2 class="text-2xl font-bold mb-6 text-blue-800">在线交流</h2>
                    
                    <!-- 发布区域 -->
                    <div class="mb-8">
                        <form id="messageForm" class="space-y-4">
                            <div>
                                <textarea 
                                    id="messageContent" 
                                    class="w-full p-4 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" 
                                    rows="3" 
                                    placeholder="分享你的想法..."
                                ></textarea>
                            </div>
                            <div class="flex justify-end">
                                <button 
                                    type="submit" 
                                    class="bg-blue-500 text-white px-6 py-2 rounded-lg hover:bg-blue-600 transition-colors"
                                >
                                    发布
                                </button>
                            </div>
                        </form>
                    </div>
                    
                    <!-- 消息列表 -->
                    <div id="messageList" class="space-y-6">
                        <!-- 消息将通过 JavaScript 动态加载 -->
                    </div>
                </div>
            `,
        };

        this.users = {
            'lzrlwt': { 
                password: 'admin123', 
                role: 'admin',
                permissions: ['view', 'edit', 'delete', 'manage_users', 'upload', 'delete_messages']
            },
            'lzr': { 
                password: 'user123', 
                role: 'user',
                permissions: ['view', 'edit', 'upload', 'delete_own_messages']
            },
            'lwt': { 
                password: 'user456', 
                role: 'limited',
                permissions: ['view', 'delete_own_messages']
            }
        };

        this.currentUser = null;
        this.questions = null;
        
        // 修改初始化方法，直接显示登录界面
        this.showLoginModal();
        this.init();
    }

    // 添加显示登录模态框的方法
    showLoginModal() {
        const loginModal = document.getElementById('loginModal');
        if (loginModal) {
            loginModal.classList.remove('hidden');
        }
    }

    init() {
        // 添加导航事件监听
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                // 如果是视频资源链接，直接跳转
                if (link.getAttribute('href') === 'videos.html') {
                    window.location.href = 'videos.html';
                    return;
                }
                const page = link.dataset.page;
                this.navigateTo(page);
            });
        });

        // 初始化路由监听
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                // 如果未登录，显示登录界面
                if (!this.currentUser) {
                    this.showLoginModal();
                    return;
                }
                const page = e.target.dataset.page;
                this.navigateTo(page);
            });
        });

        // 初始化登录模态框
        const loginModal = document.getElementById('loginModal');
        const loginForm = document.getElementById('loginForm');
        const loginBtn = document.getElementById('loginBtn');

        // 移除登录按钮的点击事件，因为我们默认显示登录界面
        loginBtn.removeEventListener('click', this.showLoginModal);

        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.querySelector('.modal-close').addEventListener('click', () => {
            // 如果未登录，不允许关闭登录界面
            if (!this.currentUser) {
                return;
            }
            loginModal.classList.add('hidden');
        });

        // 不再默认加载首页，等待登录成功后再加载
        this.updateLoginStatus();
    }

    handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (this.users[username] && this.users[username].password === password) {
            this.currentUser = {
                username: username,
                ...this.users[username]
            };
            
            // 登录成功后保存登录状态
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
            
            // 根据用户角色显示不同的欢迎信息
            let welcomeMsg = '';
            switch(this.currentUser.role) {
                case 'admin':
                    welcomeMsg = '欢迎管理员！您拥有所有权限。';
                    break;
                case 'user':
                    welcomeMsg = '欢迎用户！您可以浏览、编辑和上传内容。';
                    break;
                case 'limited':
                    welcomeMsg = '欢迎！您可以浏览内容。';
                    break;
            }
            
            document.getElementById('loginModal').classList.add('hidden');
            this.updateLoginStatus();
            this.updateUIByPermissions();
            // 登录成功后加载首页
            this.navigateTo('home');
            alert(welcomeMsg);
        } else {
            alert('用户名或密码错误！');
        }
    }

    // 更新登录状态显示
    updateLoginStatus() {
        const loginBtn = document.getElementById('loginBtn');
        if (this.currentUser) {
            loginBtn.textContent = this.currentUser.username;
            loginBtn.classList.remove('bg-blue-500', 'hover:bg-blue-600');
            loginBtn.classList.add('bg-green-500', 'hover:bg-green-600');
            
            // 添加退出按钮
            if (!document.getElementById('logoutBtn')) {
                const logoutBtn = document.createElement('button');
                logoutBtn.id = 'logoutBtn';
                logoutBtn.textContent = '退出';
                logoutBtn.className = 'bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600 ml-2';
                logoutBtn.onclick = () => this.handleLogout();
                loginBtn.parentNode.appendChild(logoutBtn);
            }
        } else {
            loginBtn.textContent = '登录';
            loginBtn.classList.remove('bg-green-500', 'hover:bg-green-600');
            loginBtn.classList.add('bg-blue-500', 'hover:bg-blue-600');
            
            // 移除退出按钮
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.remove();
            }
        }
    }

    // 根据用户权限更新UI
    updateUIByPermissions() {
        if (!this.currentUser) return;

        const permissions = this.currentUser.permissions;
        
        // 示例：根据权限显示/隐藏某些功能按钮
        const editButtons = document.querySelectorAll('.edit-btn');
        const deleteButtons = document.querySelectorAll('.delete-btn');
        const uploadButtons = document.querySelectorAll('.upload-btn');

        editButtons.forEach(btn => {
            btn.style.display = permissions.includes('edit') ? 'block' : 'none';
        });

        deleteButtons.forEach(btn => {
            btn.style.display = permissions.includes('delete') ? 'block' : 'none';
        });

        uploadButtons.forEach(btn => {
            btn.style.display = permissions.includes('upload') ? 'block' : 'none';
        });

        // 管理员特殊功能
        if (this.currentUser.role === 'admin') {
            const adminElements = document.querySelectorAll('.admin-only');
            adminElements.forEach(el => el.style.display = 'block');
        }
    }

    handleLogout() {
        this.currentUser = null;
        // 清除保存的登录状态
        localStorage.removeItem('currentUser');
        this.updateLoginStatus();
        this.updateUIByPermissions();
        this.navigateTo('home');
        alert('已成功退出登录！');
    }

    navigateTo(page) {
        // 检查是否需要登录
        if (page === 'chat' && !this.currentUser) {
            alert('请先登录后再访问在线交流！');
            this.showLoginModal();
            return;
        }

        // 原有的导航代码
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.dataset.page === page) {
                link.classList.add('active');
            }
        });

        const appContainer = document.getElementById('app');
        appContainer.innerHTML = this.pages[page] || this.pages.home;

        // 如果是聊天页面，初始化消息表单和显示消息
        if (page === 'chat') {
            this.initMessageForm();
            this.renderMessages();
        }
       
        // 如果是试题库页面，初始化答题事件
        if (page === 'resources') {
            this.initQuizEvents();
        }
    }

    initQuizEvents() {
        const quizBtns = document.querySelectorAll('.start-quiz');
        
        if (quizBtns) {
            quizBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    const chapter = btn.dataset.chapter;
                    console.log('Loading chapter:', chapter);
                    // 隐藏章节选择界面
                    document.querySelector('.grid').classList.add('hidden');
                    document.getElementById('questions-container').classList.remove('hidden');
                    this.loadQuestions(chapter);
                });
            });
        }
    }

    async loadQuestions(chapter) {
        try {
            const questions = this.quizData[chapter];
            if (!questions || questions.length === 0) {
                throw new Error('该章节暂无题目');
            }
            
            this.renderQuestions(questions);
            
            // 添加返回按钮
            const container = document.querySelector('#questions-container');
            container.insertAdjacentHTML('afterbegin', `
                <button 
                    class="back-to-chapters mb-6 bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 flex items-center"
                    onclick="document.querySelector('.grid').classList.remove('hidden'); document.getElementById('questions-container').classList.add('hidden');"
                >
                    <i class="fas fa-arrow-left mr-2"></i>
                    返回章选择
                </button>
            `);
        } catch (error) {
            console.error('加载试题失败:', error);
            document.querySelector('#questions-container').innerHTML = 
                `<div class="text-red-500 p-4 bg-red-50 rounded-lg">
                    <p class="font-bold mb-2">加载试题失败：</p>
                    <p>${error.message}</p>
                    <p class="mt-4 text-sm">请稍后再试或选择其他章节</p>
                    <button 
                        class="mt-4 bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600 flex items-center"
                        onclick="document.querySelector('.grid').classList.remove('hidden'); document.getElementById('questions-container').classList.add('hidden');"
                    >
                        <i class="fas fa-arrow-left mr-2"></i>
                        返回章节选择
                    </button>
                </div>`;
        }
    }

    renderQuestions(questions) {
        const container = document.querySelector('#questions-container');
        container.classList.remove('hidden');
        document.querySelector('.grid').classList.add('hidden');
        
        container.innerHTML = questions.map((q, index) => `
            <div class="question-card bg-white rounded-lg shadow-md p-6 mb-6">
                <div class="question-header mb-4">
                    <h3 class="text-lg font-semibold">
                        问题 ${index + 1}：${q.question}
                    </h3>
                    </div>
                <div class="options space-y-2">
                    ${q.options.map((option, i) => `
                        <div class="option flex items-center">
                            <input type="radio" 
                                id="q${index}_${i}" 
                                name="q${index}" 
                                value="${String.fromCharCode(65 + i)}"
                                class="mr-2">
                            <label for="q${index}_${i}">${option}</label>
                </div>
                    `).join('')}
                </div>
                
                <!-- 添加提交按钮 -->
                <div class="flex justify-end mt-4">
                    <button type="button" 
                        class="submit-answer bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors">
                        提交答案
                    </button>
                </div>

                <!-- 答题结果和解析区域 -->
                <div class="answer-section mt-4">
                    <!-- 答题结果显示 -->
                    <div class="result hidden mb-2"></div>
                    <!-- 答案和解析 -->
                    <div class="answer hidden p-4 bg-gray-100 rounded">
                        <p class="font-semibold text-green-600">正确答案：${q.answer}</p>
                    ${q.explanation ? `
                        <div class="text-gray-700 mt-2 pt-2 border-t border-blue-200">
                            <div class="font-semibold mb-1 text-blue-800">
                                <i class="fas fa-info-circle mr-2"></i>
                                    解析：
                            </div>
                            <div class="text-gray-600 ml-6">
                                ${q.explanation}
                            </div>
                        </div>
                    ` : ''}
                    </div>
                </div>
            </div>
        `).join('');

        // 为每个题目的提交按钮添加点击事件
        document.querySelectorAll('.question-card').forEach(card => {
            const submitBtn = card.querySelector('.submit-answer');
            const answerSection = card.querySelector('.answer');
            const resultDiv = card.querySelector('.result');
            
            if (submitBtn) {
                submitBtn.addEventListener('click', function() {
                    // 检查是否已选择答案
                    const selectedAnswer = card.querySelector('input[type="radio"]:checked');
                    if (!selectedAnswer) {
                        alert('请先选择一个答案');
                        return;
                    }
                    
                    // 显示答案和解析
                    if (answerSection) {
                        answerSection.classList.remove('hidden');
                    }
                    
                    // 检查答案是否正确并显示结果
                    const correctAnswer = card.querySelector('.text-green-600').textContent.split('：')[1];
                    resultDiv.classList.remove('hidden');
                    
                    if (selectedAnswer.value === correctAnswer) {
                        resultDiv.innerHTML = `
                            <div class="flex items-center text-green-600">
                                <i class="fas fa-check-circle mr-2"></i>
                                <span>回答正确！</span>
                            </div>`;
                } else {
                        resultDiv.innerHTML = `
                            <div class="flex items-center text-red-600">
                                <i class="fas fa-times-circle mr-2"></i>
                                <span>回答错误，您选择了 ${selectedAnswer.value}</span>
                            </div>`;
                    }
                    
                    // 禁用该题目的所有选项和提交按钮
                    card.querySelectorAll('input[type="radio"]').forEach(radio => {
                        radio.disabled = true;
                    });
                    submitBtn.disabled = true;
                    submitBtn.textContent = '已提交';
                    submitBtn.classList.add('bg-gray-500');
                    submitBtn.classList.remove('hover:bg-blue-600');
                });
            }
        });
    }

    // 修改渲染消息的方法
    renderMessages() {
        const messageList = document.getElementById('messageList');
        if (!messageList) return;

        messageList.innerHTML = this.messages.map(message => `
            <div class="message bg-gray-50 p-4 rounded-lg shadow-sm">
                <div class="flex justify-between items-start mb-2">
                    <div class="font-semibold text-blue-600">${message.author}</div>
                    <div class="text-sm text-gray-500">${message.timestamp}</div>
                </div>
                <div class="text-gray-700 mb-3">${message.content}</div>
                <div class="flex justify-between items-center">
                    <button 
                        onclick="app.likeMessage(${message.id})"
                        class="like-btn text-sm text-gray-600 hover:text-blue-500 transition-colors"
                    >
                        <i class="${message.likedBy && message.likedBy.has(this.currentUser?.username) ? 'fas' : 'far'} fa-heart mr-1"></i>
                        <span>${message.likes}</span> 赞
                    </button>
                    ${this.currentUser && (
                        (this.currentUser.username === message.author && this.currentUser.permissions.includes('delete_own_messages')) || 
                        (this.currentUser.role === 'admin' && this.currentUser.permissions.includes('delete_messages'))
                    ) ? `
                        <button 
                            onclick="app.deleteMessage(${message.id})"
                            class="delete-btn text-sm text-red-500 hover:text-red-600 transition-colors"
                        >
                            <i class="far fa-trash-alt mr-1"></i>
                            ${this.currentUser.role === 'admin' && this.currentUser.username !== message.author ? '管理员删除' : '删除'}
                        </button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    // 修改删除消息的方法
    deleteMessage(messageId) {
        const index = this.messages.findIndex(m => m.id === messageId);
        if (index !== -1) {
            const message = this.messages[index];
            const isAdmin = this.currentUser.role === 'admin';
            const isAuthor = message.author === this.currentUser.username;
            
            // 检查删除权限
            if (isAdmin || (isAuthor && this.currentUser.permissions.includes('delete_own_messages'))) {
                const confirmMessage = isAdmin && !isAuthor
                    ? '确定要删除这条用户消息吗？'
                    : '确定要删除这条消息吗？';
                
                if (confirm(confirmMessage)) {
                    this.messages.splice(index, 1);
                    this.renderMessages();
                    console.log('消息已删除'); // 添加调试信息
                }
            } else {
                console.log('没有删除权限'); // 添加调试信息
            }
        } else {
            console.log('未找到消息'); // 添加调试信息
        }
    }

    // 修改点赞功能
    likeMessage(messageId) {
        if (!this.currentUser) {
            alert('请先登录后再点赞！');
            this.showLoginModal();
            return;
        }

        const message = this.messages.find(m => m.id === messageId);
        if (message) {
            // 检查是否已经点赞过
            if (!message.likedBy) {
                message.likedBy = new Set();
            }

            if (message.likedBy.has(this.currentUser.username)) {
                message.likedBy.delete(this.currentUser.username);
                message.likes--;
            } else {
                message.likedBy.add(this.currentUser.username);
                message.likes++;
            }
            
            this.renderMessages();
        }
    }

    // 修改消息发布方法
    initMessageForm() {
        const messageForm = document.getElementById('messageForm');
        if (messageForm) {
            messageForm.addEventListener('submit', (e) => {
                e.preventDefault();
                
                const content = document.getElementById('messageContent').value.trim();
                if (!content) {
                    alert('请输入消息内容！');
                    return;
                }
                
                // 创建新消息
                const message = {
                    id: Date.now(),
                    content: content,
                    author: this.currentUser.username,
                    timestamp: new Date().toLocaleString(),
                    likes: 0,
                    likedBy: new Set()
                };
                
                // 添加到共享消息列表
                this.messages.unshift(message);
                this.renderMessages();
                
                // 清空输入框
                document.getElementById('messageContent').value = '';
            });
        }
    }

    // 添加检查登录状态的方法
    checkLoginStatus() {
        const savedUser = localStorage.getItem('currentUser');
        if (savedUser) {
            this.currentUser = JSON.parse(savedUser);
            this.updateLoginStatus();
            return true;
        }
        return false;
    }
}

// 初始化应用
new App(); 