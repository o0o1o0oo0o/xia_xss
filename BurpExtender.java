package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

/**
 * xia XSS (瞎弹) —— 仿 xia SQL(瞎注) 的 Burp 反射型 XSS 探测插件
 *
 * 思路：
 *   1. 按 Content-Type 过滤：默认只看响应 Content-Type 属于 text/html、text/javascript 等
 *      XSS 可解析类型的流量（可在界面切换为「按请求 Content-Type 判定」）；
 *   2. 取出 URL / Body / JSON / XML / Cookie 参数，逐个把参数值替换成随机字符串；
 *   3. 重新发包，响应中若出现这串随机字符 -> 打勾（反射点），并记录反射上下文；
 *   4. 支持自定义 XSS 语句，用 %s / {RAND} 占位随机串。
 *
 * 与 xia SQL 保持一致：legacy Burp API（IBurpExtender）、单文件、JDK 1.8 可编译、
 * 双表格 + Request/Response 查看器、右键 Send to、MD5 去重、白名单、payload 存 ini。
 *
 * 仅供授权范围内的安全测试使用。
 */
public class BurpExtender extends AbstractTableModel
        implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController {

    private static final String EXT_NAME = "xia XSS";
    private static final String VERSION = "1.0";
    /** 右键 "Send to xia XSS" 的自定义来源标记，与 xia SQL 一样复用 1024 */
    private static final int FORCE_SCAN = 1024;
    private static final String CONFIG_FILE_DEFAULT = "xia_XSS_config.ini";
    private static final String PAYLOAD_FILE_DEFAULT = "xia_XSS_diy_payload.ini";

    /** 默认认为浏览器可解析 / 值得探测的类型 */
    private static final String DEFAULT_TYPES =
            "text/html,application/xhtml+xml,text/plain,text/javascript,application/javascript," +
            "application/x-javascript,text/ecmascript,application/ecmascript,text/xml," +
            "application/xml,application/*+xml,image/svg+xml,application/rss+xml";
    /** 默认跳过会破坏会话、签名、上传的参数 */
    private static final String DEFAULT_SKIP_PARAMS =
            "token,csrf,_csrf,csrf_token,nonce,sign,signature,sig,captcha,verifycode," +
            "password,passwd,pwd,secret,__viewstate,__eventvalidation,file,upload";
    /** 默认排除的路径关键词：增删改 / 注册等添加或修改性接口（分段精确匹配，可在界面自定义） */
    private static final String DEFAULT_EXCLUDE_PATHS =
            "add,create,new,insert,save,edit,update,modify,del,delete,remove,destroy," +
            "register,signup,upload,import,bind";
    /** 默认排除的资源类型后缀（js / ts 等前端与静态资源，可在界面自定义） */
    private static final String DEFAULT_SKIP_EXTS =
            "js,ts,jsx,tsx,mjs,cjs,map,css,woff,woff2,ttf,eot,otf,jpg,jpeg,png,gif,ico,webp,bmp," +
            "mp3,mp4,avi,mov,wmv,pdf,zip,rar,7z,gz,tar,exe,dll,doc,docx,xls,xlsx,ppt,pptx,apk,iso,bin,swf";
    private static final String DEFAULT_PAYLOAD_TEXT =
            "# 每行一条 XSS 语句，%s 或 {RAND} 会被替换成本次探测的随机字符串\n" +
            "# {V} 代表参数原值；# 开头为注释\n" +
            "\"><svg onload=alert(%s)>\n" +
            "\"><img src=x onerror=alert(%s)>\n" +
            "'\"><script>/*%s*/alert(1)</script>\n";

    // ------------------------------------------------------------------
    // Burp 运行时对象
    // ------------------------------------------------------------------
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // ------------------------------------------------------------------
    // UI
    // ------------------------------------------------------------------
    /** 插件主界面：单 Burp Tab，内含「请求」「配置」两个子目录 */
    private Component uiRoot;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private MainTable logTable;
    private DetailTable detailTable;
    private final DetailModel detailModel = new DetailModel();
    private JLabel lblStat;

    private JCheckBox chkEnabled, chkProxy, chkRepeater, chkOther, chkCookie, chkStatic,
            chkBinary, chkEncode, chkAppend, chkMissingCT, chkCustom, chkKeepProbe;
    private JTextField txtWhitelist, txtExcludeHosts, txtAllowPorts, txtDenyPorts,
            txtMethods, txtReqTypes, txtSkipParams, txtRandomLen, txtMaxParams,
            txtMaxRespKB, txtThreads, txtDelay, txtExcludePaths, txtSkipExts;
    private JButton btnWhitelist;
    private JComboBox<String> cmbMode;
    private JTextArea txtPayload;
    /** XSS 可解析类型：多行展示默认值，可直接编辑 */
    private JTextArea txtTypes;

    /** 防止「把配置回填到 UI」的过程里反复触发 syncConfig */
    private volatile boolean uiLoading = false;

    // ------------------------------------------------------------------
    // 状态
    // ------------------------------------------------------------------
    private volatile Config cfg = Config.defaults();
    private final List<LogEntry> log = new CopyOnWriteArrayList<LogEntry>();
    private final List<ProbeEntry> probes = new CopyOnWriteArrayList<ProbeEntry>();
    /** 明细表当前展示的探测记录，只在 EDT 访问 */
    private final List<ProbeEntry> shown = new ArrayList<ProbeEntry>();
    /** 去重：MD5(不带参数的 URL + 参数名/位置 + 方法)，并发安全 */
    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final AtomicInteger seq = new AtomicInteger(1);
    private final SecureRandom random = new SecureRandom();
    private volatile String selectedMd5;
    private volatile int selectedRow = -1;
    private volatile ThreadPoolExecutor pool;

    // ==================================================================
    // 入口
    // ==================================================================
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName(EXT_NAME + " V" + VERSION);
        stdout.println("hello xia xss!");
        stdout.println("xia XSS V" + VERSION + " 已加载 | 配置文件: " + configFile().getAbsolutePath());
        stdout.println("原理：逐个把参数值替换为随机字符，返回包包含该随机字符则标记 ✔");
        stdout.println("提示：XSS 能否被浏览器解析由【响应】Content-Type 决定，默认按响应判定；右侧可切换为按请求判定。");
        stdout.println("默认支持的类型（界面可改，支持 * 通配）：" + DEFAULT_TYPES);

        loadConfig();
        loadPayloadFile();
        rebuildPool();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                buildMainUi();
                callbacks.customizeUiComponent(uiRoot);
                callbacks.addSuiteTab(BurpExtender.this);   // 单 Tab：「请求」/「配置」两个子目录
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);
                refreshTables();
            }
        });
    }

    // ==================================================================
    // UI 构建（参考 HaE）：单个 Burp Tab「xia XSS」，内部分「请求」「配置」两个子目录
    //   请求：上=原始流量|探测明细（可拖动），下=请求/响应并排，底部状态条
    //   配置：HaE 风格分组面板（监控与处理 / Content-Type / 范围过滤 / 性能与操作 / 自定义payload）
    // ==================================================================
    private void buildMainUi() {
        // ---- 请求页 ----
        //上半：原始流量 | 探测明细，中间分隔条可拖动
        JSplitPane tables = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        logTable = new MainTable(this);
        detailTable = new DetailTable(detailModel);
        logTable.setComponentPopupMenu(mainPopupMenu());
        detailTable.setComponentPopupMenu(detailPopupMenu());
        tables.setLeftComponent(new JScrollPane(logTable));
        tables.setRightComponent(new JScrollPane(detailTable));
        tables.setResizeWeight(0.5);
        guardDivider(tables, 0.5);

        //下半：请求 / 响应包并排同时显示
        requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
        responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(BorderFactory.createTitledBorder("请求包"));
        reqPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);
        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(BorderFactory.createTitledBorder("响应包"));
        respPanel.add(responseViewer.getComponent(), BorderLayout.CENTER);
        JSplitPane viewers = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        viewers.setLeftComponent(reqPanel);
        viewers.setRightComponent(respPanel);
        viewers.setResizeWeight(0.5);
        guardDivider(viewers, 0.5);

        JSplitPane dataSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        dataSplit.setLeftComponent(tables);
        dataSplit.setRightComponent(viewers);
        dataSplit.setResizeWeight(0.6);
        guardDivider(dataSplit, 0.4);

        //底部状态条：版本 / 状态 + 清空列表，请求页常驻可见
        JPanel status = new JPanel(new BorderLayout(4, 0));
        status.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        lblStat = new JLabel("xia XSS V" + VERSION + " · 就绪");
        JButton btnClear = new JButton("清空列表");
        btnClear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearAll();
            }
        });
        status.add(lblStat, BorderLayout.CENTER);
        status.add(btnClear, BorderLayout.EAST);

        JPanel dataPane = new JPanel(new BorderLayout());
        dataPane.add(dataSplit, BorderLayout.CENTER);
        dataPane.add(status, BorderLayout.SOUTH);

        // ---- 外层：请求 / 配置 两个子目录 ----
        JTabbedPane root = new JTabbedPane();
        root.addTab("请求", dataPane);
        root.addTab("配置", buildConfigUi(cfg));
        uiRoot = root;
    }

    /** 配置页：上方四个分组面板 2x2 排布，下方自定义 payload，中间可拖动 */
    private Component buildConfigUi(Config c) {
        JPanel top = new JPanel(new GridLayout(2, 2, 8, 8));
        top.add(buildMonitorGroup(c));
        top.add(buildCtGroup(c));
        top.add(buildScopeGroup(c));
        top.add(buildPerfGroup(c));

        JPanel payloadGroup = new JPanel(new BorderLayout());
        payloadGroup.setBorder(BorderFactory.createTitledBorder("自定义 payload"));
        payloadGroup.add(buildPayloadPanel(c), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setLeftComponent(top);
        split.setRightComponent(payloadGroup);
        split.setResizeWeight(0.6);
        guardDivider(split, 0.6);
        return split;
    }

    // ------------------------------------------------------------------
    // HaE 风格分组表单：标题边框分组 + 右对齐标签 + 横向填满的控件
    // ------------------------------------------------------------------

    /** 分组容器：带标题边框 */
    private JPanel group(String title) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        return p;
    }

    /**
     * JSplitPane 在 tab 隐藏期间尺寸变为 0，重新显示时分隔条可能被挤到边缘导致内容塌陷。
     * 监听显示事件：分隔条贴边时按比例复位，正常拖动过的位置保持不动。
     */
    private void guardDivider(final JSplitPane sp, final double ratio) {
        sp.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        int size = sp.getHeight() - 2 * sp.getDividerSize();
                        if (size > 50) {
                            int loc = sp.getDividerLocation();
                            if (loc < 10 || loc > size - 10) {
                                sp.setDividerLocation(ratio);
                            }
                        }
                    }
                });
            }
        });
    }

    /** 表单行：右对齐标签 + 横向填满的控件，返回下一行号 */
    private int formRow(JPanel g, int row, String label, JComponent field, String tooltip) {
        field.setToolTipText(tooltip == null ? label : tooltip);
        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0;
        lc.gridy = row;
        lc.anchor = GridBagConstraints.EAST;
        lc.insets = new Insets(3, 8, 3, 6);
        g.add(new JLabel(label), lc);
        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1;
        fc.gridy = row;
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(3, 0, 3, 8);
        g.add(field, fc);
        return row + 1;
    }

    private JTextField formField(String value, String tooltip) {
        JTextField field = new JTextField(value == null ? "" : value, 10);
        // 固定列数：首选宽度不随内容长度变化，避免长配置项撑乱 GridBag 网格
        field.setColumns(10);
        field.getDocument().addDocumentListener(new SyncDocListener());
        field.setToolTipText(tooltip);
        return field;
    }

    private JCheckBox formCheck(JPanel parent, String text, boolean selected) {
        JCheckBox box = new JCheckBox(text, selected);
        box.addItemListener(new SyncListener());
        if (parent != null) {
            parent.add(box);
        }
        return box;
    }

    /** 监控开关切换时输出日志，让"开关是否生效"立即可见 */
    private void addMonitorLog(final JCheckBox box, final String name) {
        box.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                stdout.println("监控 " + name + "：" + (box.isSelected() ? "已开启（立即生效）" : "已关闭"));
            }
        });
    }

    /** 监控与处理：所有开关两列排布 */
    private JPanel buildMonitorGroup(Config c) {
        JPanel checks = new JPanel(new GridLayout(0, 2, 8, 4));
        chkEnabled = formCheck(checks, "启动插件（总开关）", c.enabled);
        //总开关立即生效：关闭时清空排队任务，进行中的探测在当前请求后停止
        chkEnabled.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (!chkEnabled.isSelected()) {
                    ThreadPoolExecutor tp = pool;
                    if (tp != null) {
                        int queued = tp.getQueue().size();
                        tp.getQueue().clear();
                        stdout.println("插件已关闭：清空排队任务 " + queued + " 个，进行中的探测立即中止");
                    }
                    setStatus("插件已关闭，扫描停止");
                }
            }
        });
        chkProxy = formCheck(checks, "监控 Proxy", c.monitorProxy);
        addMonitorLog(chkProxy, "Proxy");
        chkRepeater = formCheck(checks, "监控 Repeater", c.monitorRepeater);
        addMonitorLog(chkRepeater, "Repeater");
        chkOther = formCheck(checks, "监控 Scanner / Intruder / Target", c.monitorOther);
        addMonitorLog(chkOther, "Scanner/Intruder/Target");
        chkCookie = formCheck(checks, "测试 Cookie 参数", c.testCookie);
        chkStatic = formCheck(checks, "排除静态资源类型", c.skipStatic);
        chkBinary = formCheck(checks, "跳过二进制请求 / 响应", c.skipBinary);
        chkEncode = formCheck(checks, "按参数类型自动编码 payload", c.encodePayload);
        chkAppend = formCheck(checks, "追加模式（保留原值）", c.appendMode);
        chkMissingCT = formCheck(checks, "允许响应缺少 Content-Type", c.allowMissingCT);

        JPanel p = group("监控与处理");
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.gridy = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 1.0;
        gc.anchor = GridBagConstraints.NORTH;
        gc.insets = new Insets(4, 4, 6, 6);
        p.add(checks, gc);
        return p;
    }

    /** Content-Type 组：判定依据 + 可解析类型列表（可直接修改、一键恢复默认） */
    private JPanel buildCtGroup(Config c) {
        JPanel p = group("Content-Type 判定");
        int row = 0;
        cmbMode = new JComboBox<String>(new String[]{
                "按响应（推荐）", "按请求", "任一满足", "两者都满足"});
        cmbMode.setSelectedIndex(clamp(c.ctMode, 0, 3));
        cmbMode.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                syncConfig();
            }
        });
        row = formRow(p, row, "判定依据", cmbMode,
                "XSS 能否被浏览器解析由响应 Content-Type 决定，推荐按响应判定");

        // 行换行的 JTextArea 在 GridBag+JScrollPane 里会产生"宽度<->换行<->滚动条"的
        // 首选尺寸振荡，tab 隐藏/显示触发反复验证时直接把 EDT 卡死。
        // 这里：首选尺寸改为常量、强制宽度跟随视口，彻底掐断振荡源
        txtTypes = new JTextArea(c.responseTypes == null ? "" : c.responseTypes, 4, 20) {
            @Override
            public Dimension getPreferredSize() {
                return new Dimension(220, 100);
            }

            @Override
            public boolean getScrollableTracksViewportWidth() {
                return true;
            }
        };
        txtTypes.setLineWrap(true);
        txtTypes.setWrapStyleWord(true);
        txtTypes.getDocument().addDocumentListener(new SyncDocListener());
        txtTypes.setToolTipText("XSS 可解析类型，逗号分隔，支持 * 通配。默认：" + DEFAULT_TYPES);
        JButton btnResetTypes = new JButton("恢复默认类型");
        btnResetTypes.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                txtTypes.setText(DEFAULT_TYPES);
                stdout.println("已恢复默认 XSS 可解析类型：" + DEFAULT_TYPES);
            }
        });
        JPanel typesWrap = new JPanel(new BorderLayout(0, 2));
        typesWrap.add(new JScrollPane(txtTypes), BorderLayout.CENTER);
        typesWrap.add(btnResetTypes, BorderLayout.SOUTH);

        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0;
        lc.gridy = row;
        lc.anchor = GridBagConstraints.EAST;
        lc.insets = new Insets(3, 8, 3, 6);
        p.add(new JLabel("可解析类型"), lc);
        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1;
        fc.gridy = row;
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(3, 0, 3, 8);
        p.add(typesWrap, fc);
        return p;
    }

    /** 范围过滤组：域名白/黑名单 / 排除路径 / 资源类型 / 请求方法 / 参数名 */
    private JPanel buildScopeGroup(Config c) {
        JPanel p = group("范围过滤");
        int row = 0;

        txtWhitelist = formField(c.whitelist, "开启后只测试列表内域名。多个用逗号隔开，支持 *.example.com");
        btnWhitelist = new JButton(c.whitelistOn ? "关闭白名单" : "启动白名单");
        btnWhitelist.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean on = btnWhitelist.getText().equals("启动白名单");
                btnWhitelist.setText(on ? "关闭白名单" : "启动白名单");
                txtWhitelist.setEditable(!on);
                stdout.println(on ? "启动白名单：" + txtWhitelist.getText() : "关闭白名单");
                syncConfig();
            }
        });
        JPanel wl = new JPanel(new BorderLayout(4, 0));
        wl.add(txtWhitelist, BorderLayout.CENTER);
        wl.add(btnWhitelist, BorderLayout.EAST);
        row = formRow(p, row, "域名白名单", wl, null);
        txtWhitelist.setEditable(!c.whitelistOn);

        txtExcludeHosts = formField(c.excludeHosts,
                "黑名单内的域名不测试。多个用逗号隔开，支持 *.example.com。"
                        + "默认已排除教育（edu.cn）、政府（gov.cn）等敏感单位，可自行增删");
        row = formRow(p, row, "域名黑名单", txtExcludeHosts, null);

        txtExcludePaths = formField(c.excludePaths,
                "增删改/注册等添加或修改性接口不测试。关键词含 / 时按路径包含匹配（如 /api/user/add），"
                        + "否则按 / _ - . 分段精确匹配（add 可命中 /user/add，不会误伤 /addressbook）。逗号分隔，可自定义");
        row = formRow(p, row, "排除路径", txtExcludePaths, null);

        txtSkipExts = formField(c.skipExts,
                "排除的 URL 后缀，逗号分隔，可自定义。默认含 js,ts,jsx,tsx 等前端资源和常见静态类型；"
                        + "需配合「监控与处理」里的「排除静态资源类型」开关生效");
        row = formRow(p, row, "资源类型列表", txtSkipExts, null);

        txtMethods = formField(c.methods, "只测试这些方法，留空=全部，如 GET,POST");
        row = formRow(p, row, "请求方法", txtMethods, null);

        JPanel ports = new JPanel(new GridLayout(1, 2, 4, 0));
        txtAllowPorts = formField(c.allowPorts, "端口白名单：留空=全部端口，如 80,443,8080");
        txtDenyPorts = formField(c.denyPorts, "排除端口：多个端口用逗号隔开");
        ports.add(txtAllowPorts);
        ports.add(txtDenyPorts);
        row = formRow(p, row, "端口白/黑名单", ports, "左=端口白名单（留空=全部）；右=排除端口");

        txtSkipParams = formField(c.skipParams,
                "逗号分隔，参数名包含即跳过（默认已排除 token/csrf/password 等）");
        row = formRow(p, row, "跳过参数名", txtSkipParams, null);
        return p;
    }

    /** 性能与操作组：载荷长度 / 并发 / 配置持久化按钮 */
    private JPanel buildPerfGroup(Config c) {
        JPanel p = group("性能与操作");
        int row = 0;
        txtRandomLen = formField(String.valueOf(c.randomLen), "纯随机字母数字的长度，4-32");
        row = formRow(p, row, "随机串长度", txtRandomLen, null);
        txtMaxParams = formField(String.valueOf(c.maxParams), "1-200");
        row = formRow(p, row, "单请求最多参数数", txtMaxParams, null);
        txtMaxRespKB = formField(String.valueOf(c.maxResponseKB), "响应体超出则跳过，16-8192");
        row = formRow(p, row, "最大响应 KB", txtMaxRespKB, null);
        txtThreads = formField(String.valueOf(c.threads), "点【应用线程数】后生效");
        row = formRow(p, row, "并发线程数", txtThreads, null);
        txtDelay = formField(String.valueOf(c.delayMs), "每个探测请求的间隔，0-5000");
        row = formRow(p, row, "请求间隔 ms", txtDelay, null);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton btnSave = new JButton("保存启动参数");
        JButton btnReload = new JButton("重载配置");
        JButton btnPool = new JButton("应用线程数");
        btnSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                syncConfig();
                saveConfig();
                savePayloadFile();
                rebuildPool();
                stdout.println("启动参数已保存到 " + configFile().getAbsolutePath());
            }
        });
        btnReload.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loadConfig();
                loadPayloadFile();
                applyConfigToUi();
                rebuildPool();
                stdout.println("配置已重载");
            }
        });
        btnPool.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                syncConfig();
                rebuildPool();
                stdout.println("线程池已重建，并发=" + cfg.threads);
            }
        });
        buttons.add(btnSave);
        buttons.add(btnReload);
        buttons.add(btnPool);
        GridBagConstraints bc = new GridBagConstraints();
        bc.gridx = 0;
        bc.gridy = row;
        bc.gridwidth = 2;
        bc.anchor = GridBagConstraints.WEST;
        bc.insets = new Insets(4, 8, 4, 8);
        p.add(buttons, bc);
        return p;
    }

    private JPanel buildPayloadPanel(Config c) {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        chkCustom = new JCheckBox("启用自定义 xss payload", c.customEnabled);
        chkCustom.addItemListener(new SyncListener());
        chkKeepProbe = new JCheckBox("同时保留随机探测", c.keepProbe);
        chkKeepProbe.addItemListener(new SyncListener());
        JButton btnSavePayload = new JButton("加载/重新加载 payload");
        btnSavePayload.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                savePayloadFile();
                syncConfig();
                stdout.println("自定义 payload 已加载并保存到 " + payloadFile().getAbsolutePath());
            }
        });
        top.add(chkCustom);
        top.add(chkKeepProbe);
        top.add(btnSavePayload);

        txtPayload = new JTextArea(c.payloadText, 16, 30);
        txtPayload.setLineWrap(false);
        txtPayload.setEditable(c.customEnabled);
        txtPayload.getDocument().addDocumentListener(new SyncDocListener());

        JLabel hint = new JLabel("占位符：%s 或 {RAND} = 本次随机字符串；{V} = 参数原值；# 开头为注释");
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(txtPayload), BorderLayout.CENTER);
        p.add(hint, BorderLayout.SOUTH);
        return p;
    }

    private class SyncListener implements ItemListener {
        @Override
        public void itemStateChanged(ItemEvent e) {
            if (e.getSource() == chkCustom && txtPayload != null) {
                txtPayload.setEditable(chkCustom.isSelected());
            }
            syncConfig();
        }
    }

    private class SyncDocListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent e) {
            syncConfig();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            syncConfig();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            syncConfig();
        }
    }

    // ==================================================================
    // 启动参数：xia_XSS_config.ini，可用 -Dxiaxss.config=<path> / -Dxiaxss.payload=<path> 覆盖
    // ==================================================================
    private File configFile() {
        return new File(System.getProperty("xiaxss.config", CONFIG_FILE_DEFAULT));
    }

    private File payloadFile() {
        String p = System.getProperty("xiaxss.payload");
        if (p != null && p.trim().length() > 0) {
            return new File(p);
        }
        File parent = configFile().getAbsoluteFile().getParentFile();
        return parent == null ? new File(PAYLOAD_FILE_DEFAULT) : new File(parent, PAYLOAD_FILE_DEFAULT);
    }

    private void loadConfig() {
        Config c = Config.defaults();
        File f = configFile();
        if (f.isFile()) {
            Properties props = new Properties();
            try {
                BufferedReader r = new BufferedReader(
                        new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
                try {
                    props.load(r);
                } finally {
                    r.close();
                }
                c.enabled = bool(props, "enabled", c.enabled);
                c.monitorProxy = bool(props, "monitor.proxy", c.monitorProxy);
                c.monitorRepeater = bool(props, "monitor.repeater", c.monitorRepeater);
                c.monitorOther = bool(props, "monitor.other", c.monitorOther);
                c.testCookie = bool(props, "test.cookie", c.testCookie);
                c.skipStatic = bool(props, "skip.static", c.skipStatic);
                c.skipBinary = bool(props, "skip.binary", c.skipBinary);
                c.encodePayload = bool(props, "encode.payload", c.encodePayload);
                c.appendMode = bool(props, "append.mode", c.appendMode);
                c.allowMissingCT = bool(props, "allow.missing.ct", c.allowMissingCT);
                c.whitelistOn = bool(props, "whitelist.on", c.whitelistOn);
                c.customEnabled = bool(props, "custom.enabled", c.customEnabled);
                c.keepProbe = bool(props, "custom.keep.probe", c.keepProbe);
                c.whitelist = str(props, "whitelist", c.whitelist);
                c.excludeHosts = str(props, "exclude.hosts", c.excludeHosts);
                c.allowPorts = str(props, "allow.ports", c.allowPorts);
                c.denyPorts = str(props, "deny.ports", c.denyPorts);
                c.methods = str(props, "methods", c.methods);
                c.responseTypes = str(props, "types", c.responseTypes);
                c.requestTypes = str(props, "request.types", c.requestTypes);
                c.skipParams = str(props, "skip.params", c.skipParams);
                c.excludePaths = str(props, "exclude.paths", c.excludePaths);
                c.skipExts = str(props, "skip.exts", c.skipExts);
                c.ctMode = clamp(intVal(props.getProperty("ct.mode"), c.ctMode), 0, 3);
                c.randomLen = clamp(intVal(props.getProperty("random.len"), c.randomLen), 4, 32);
                c.maxParams = clamp(intVal(props.getProperty("max.params"), c.maxParams), 1, 200);
                c.maxResponseKB = clamp(intVal(props.getProperty("max.response.kb"), c.maxResponseKB), 16, 8192);
                c.threads = clamp(intVal(props.getProperty("threads"), c.threads), 1, 16);
                c.delayMs = clamp(intVal(props.getProperty("delay.ms"), c.delayMs), 0, 5000);
                stdout.println("已读取启动参数：" + f.getAbsolutePath());
            } catch (Exception ex) {
                stdout.println("读取启动参数失败，使用默认值：" + ex);
            }
        }
        cfg = c;
    }

    private void saveConfig() {
        Config c = cfg;
        Properties props = new Properties();
        props.setProperty("enabled", String.valueOf(c.enabled));
        props.setProperty("monitor.proxy", String.valueOf(c.monitorProxy));
        props.setProperty("monitor.repeater", String.valueOf(c.monitorRepeater));
        props.setProperty("monitor.other", String.valueOf(c.monitorOther));
        props.setProperty("test.cookie", String.valueOf(c.testCookie));
        props.setProperty("skip.static", String.valueOf(c.skipStatic));
        props.setProperty("skip.binary", String.valueOf(c.skipBinary));
        props.setProperty("encode.payload", String.valueOf(c.encodePayload));
        props.setProperty("append.mode", String.valueOf(c.appendMode));
        props.setProperty("allow.missing.ct", String.valueOf(c.allowMissingCT));
        props.setProperty("whitelist.on", String.valueOf(c.whitelistOn));
        props.setProperty("custom.enabled", String.valueOf(c.customEnabled));
        props.setProperty("custom.keep.probe", String.valueOf(c.keepProbe));
        props.setProperty("whitelist", c.whitelist);
        props.setProperty("exclude.hosts", c.excludeHosts);
        props.setProperty("allow.ports", c.allowPorts);
        props.setProperty("deny.ports", c.denyPorts);
        props.setProperty("methods", c.methods);
        props.setProperty("types", c.responseTypes);
        props.setProperty("request.types", c.requestTypes);
        props.setProperty("skip.params", c.skipParams);
        props.setProperty("exclude.paths", c.excludePaths);
        props.setProperty("skip.exts", c.skipExts);
        props.setProperty("ct.mode", String.valueOf(c.ctMode));
        props.setProperty("random.len", String.valueOf(c.randomLen));
        props.setProperty("max.params", String.valueOf(c.maxParams));
        props.setProperty("max.response.kb", String.valueOf(c.maxResponseKB));
        props.setProperty("threads", String.valueOf(c.threads));
        props.setProperty("delay.ms", String.valueOf(c.delayMs));
        try {
            Writer w = new OutputStreamWriter(new FileOutputStream(configFile()), StandardCharsets.UTF_8);
            try {
                props.store(w, "xia XSS 启动参数 | 可用 -Dxiaxss.config=<path> 指定");
            } finally {
                w.close();
            }
        } catch (Exception ex) {
            stdout.println("保存启动参数失败：" + ex);
        }
    }

    private void loadPayloadFile() {
        File f = payloadFile();
        StringBuilder sb = new StringBuilder();
        if (f.isFile()) {
            try {
                BufferedReader r = new BufferedReader(
                        new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
                try {
                    String line;
                    while ((line = r.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                } finally {
                    r.close();
                }
            } catch (Exception ex) {
                stdout.println("读取 payload 失败：" + ex);
            }
        }
        Config c = new Config();
        Config old = cfg;
        copy(old, c);
        c.payloadText = sb.length() == 0 ? DEFAULT_PAYLOAD_TEXT : sb.toString();
        cfg = c;
        if (txtPayload != null) {
            txtPayload.setText(cfg.payloadText);
        }
    }

    /** 复制配置（loadPayloadFile 需要保留已加载的启动参数） */
    private static void copy(Config from, Config to) {
        to.enabled = from.enabled;
        to.monitorProxy = from.monitorProxy;
        to.monitorRepeater = from.monitorRepeater;
        to.monitorOther = from.monitorOther;
        to.testCookie = from.testCookie;
        to.skipStatic = from.skipStatic;
        to.skipBinary = from.skipBinary;
        to.encodePayload = from.encodePayload;
        to.appendMode = from.appendMode;
        to.allowMissingCT = from.allowMissingCT;
        to.whitelistOn = from.whitelistOn;
        to.customEnabled = from.customEnabled;
        to.keepProbe = from.keepProbe;
        to.whitelist = from.whitelist;
        to.excludeHosts = from.excludeHosts;
        to.allowPorts = from.allowPorts;
        to.denyPorts = from.denyPorts;
        to.methods = from.methods;
        to.responseTypes = from.responseTypes;
        to.requestTypes = from.requestTypes;
        to.skipParams = from.skipParams;
        to.excludePaths = from.excludePaths;
        to.skipExts = from.skipExts;
        to.payloadText = from.payloadText;
        to.ctMode = from.ctMode;
        to.randomLen = from.randomLen;
        to.maxParams = from.maxParams;
        to.maxResponseKB = from.maxResponseKB;
        to.threads = from.threads;
        to.delayMs = from.delayMs;
    }

    private void savePayloadFile() {
        try {
            Writer w = new OutputStreamWriter(new FileOutputStream(payloadFile()), StandardCharsets.UTF_8);
            try {
                w.write(txtPayload.getText());
            } finally {
                w.close();
            }
        } catch (Exception ex) {
            stdout.println("保存 payload 失败：" + ex);
        }
    }

    private static boolean bool(Properties p, String k, boolean def) {
        String v = p.getProperty(k);
        return v == null ? def : "true".equalsIgnoreCase(v.trim());
    }

    private static String str(Properties p, String k, String def) {
        String v = p.getProperty(k);
        return v == null ? def : v;
    }

    private static int intVal(String s, int def) {
        if (s == null) {
            return def;
        }
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static int clamp(int v, int min, int max) {
        return v < min ? min : (v > max ? max : v);
    }

    /** UI -> 配置（copy-on-write，工作线程只读快照） */
    private void syncConfig() {
        if (uiLoading || chkEnabled == null || txtPayload == null) {
            return;
        }
        Config c = new Config();
        c.enabled = chkEnabled.isSelected();
        c.monitorProxy = chkProxy.isSelected();
        c.monitorRepeater = chkRepeater.isSelected();
        c.monitorOther = chkOther.isSelected();
        c.testCookie = chkCookie.isSelected();
        c.skipStatic = chkStatic.isSelected();
        c.skipBinary = chkBinary.isSelected();
        c.encodePayload = chkEncode.isSelected();
        c.appendMode = chkAppend.isSelected();
        c.allowMissingCT = chkMissingCT.isSelected();
        c.whitelistOn = btnWhitelist.getText().equals("关闭白名单");
        c.customEnabled = chkCustom.isSelected();
        c.keepProbe = chkKeepProbe.isSelected();
        c.whitelist = txtWhitelist.getText();
        c.excludeHosts = txtExcludeHosts.getText();
        c.allowPorts = txtAllowPorts.getText();
        c.denyPorts = txtDenyPorts.getText();
        c.methods = txtMethods.getText();
        c.responseTypes = txtTypes.getText();
        c.requestTypes = txtReqTypes.getText();
        c.skipParams = txtSkipParams.getText();
        c.excludePaths = txtExcludePaths.getText();
        c.skipExts = txtSkipExts.getText();
        c.ctMode = cmbMode.getSelectedIndex();
        c.randomLen = clamp(intVal(txtRandomLen.getText(), 10), 4, 32);
        c.maxParams = clamp(intVal(txtMaxParams.getText(), 30), 1, 200);
        c.maxResponseKB = clamp(intVal(txtMaxRespKB.getText(), 512), 16, 8192);
        c.threads = clamp(intVal(txtThreads.getText(), 4), 1, 16);
        c.delayMs = clamp(intVal(txtDelay.getText(), 0), 0, 5000);
        c.payloadText = txtPayload.getText();
        cfg = c;
    }

    /** 配置 -> UI（重载配置时用） */
    private void applyConfigToUi() {
        if (chkEnabled == null || txtPayload == null) {
            return;
        }
        uiLoading = true;
        try {
            Config c = cfg;
            chkEnabled.setSelected(c.enabled);
            chkProxy.setSelected(c.monitorProxy);
            chkRepeater.setSelected(c.monitorRepeater);
            chkOther.setSelected(c.monitorOther);
            chkCookie.setSelected(c.testCookie);
            chkStatic.setSelected(c.skipStatic);
            chkBinary.setSelected(c.skipBinary);
            chkEncode.setSelected(c.encodePayload);
            chkAppend.setSelected(c.appendMode);
            chkMissingCT.setSelected(c.allowMissingCT);
            btnWhitelist.setText(c.whitelistOn ? "关闭白名单" : "启动白名单");
            txtWhitelist.setText(c.whitelist);
            txtWhitelist.setEditable(!c.whitelistOn);
            txtExcludeHosts.setText(c.excludeHosts);
            txtAllowPorts.setText(c.allowPorts);
            txtDenyPorts.setText(c.denyPorts);
            txtMethods.setText(c.methods);
            txtTypes.setText(c.responseTypes);
            txtReqTypes.setText(c.requestTypes);
            txtSkipParams.setText(c.skipParams);
            txtExcludePaths.setText(c.excludePaths);
            txtSkipExts.setText(c.skipExts);
            cmbMode.setSelectedIndex(clamp(c.ctMode, 0, 3));
            txtRandomLen.setText(String.valueOf(c.randomLen));
            txtMaxParams.setText(String.valueOf(c.maxParams));
            txtMaxRespKB.setText(String.valueOf(c.maxResponseKB));
            txtThreads.setText(String.valueOf(c.threads));
            txtDelay.setText(String.valueOf(c.delayMs));
            chkCustom.setSelected(c.customEnabled);
            chkKeepProbe.setSelected(c.keepProbe);
            txtPayload.setText(c.payloadText);
            txtPayload.setEditable(c.customEnabled);
        } finally {
            // 必须保证 uiLoading 被复位，否则之后所有 UI 修改都无法同步到 cfg
            uiLoading = false;
            syncConfig();
        }
    }

    private void rebuildPool() {
        final int n = cfg.threads;
        ThreadPoolExecutor old = pool;
        pool = new ThreadPoolExecutor(n, n, 60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(500),
                new ThreadFactory() {
                    private final AtomicInteger id = new AtomicInteger(1);

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "xia-xss-" + id.getAndIncrement());
                        t.setDaemon(true);
                        return t;
                    }
                },
                new RejectedExecutionHandler() {
                    @Override
                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                        stdout.println("队列已满，丢弃一个扫描任务（可调大线程数或缩小监控范围）");
                    }
                });
        if (old != null) {
            old.shutdown();
        }
    }

    private void clearAll() {
        log.clear();
        probes.clear();
        shown.clear();
        seen.clear();
        seq.set(1);
        selectedMd5 = null;
        selectedRow = -1;
        refreshTables();
        stdout.println("列表与去重记录已清空");
    }

    // ==================================================================
    // 流量入口
    // ==================================================================
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return;
        }
        Config c = cfg;
        if (!c.enabled) {
            return;
        }
        boolean monitored =
                (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && c.monitorProxy)
                        || (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && c.monitorRepeater)
                        || (c.monitorOther && (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER
                        || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER
                        || toolFlag == IBurpExtenderCallbacks.TOOL_TARGET
                        || toolFlag == 8 /* TOOL_SPIDER */));
        if (!monitored) {
            return;
        }
        // 插件自己发出的探测包 toolFlag = TOOL_EXTENDER(1024)，不会命中上面的开关，避免递归
        submit(messageInfo, toolFlag);
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<JMenuItem>();
        final IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return items;
        }
        JMenuItem item = new JMenuItem("Send to " + EXT_NAME);
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!cfg.enabled) {
                    stdout.println("插件处于关闭状态，先勾选「启动插件」");
                    return;
                }
                for (IHttpRequestResponse rr : selected) {
                    // 右键强制重扫：跳过去重，且不受静态后缀限制
                    submit(rr, FORCE_SCAN);
                }
            }
        });
        items.add(item);
        return items;
    }

    private void submit(final IHttpRequestResponse base, final int toolFlag) {
        if (base == null || pool == null) {
            return;
        }
        // 先做内存快照，避免 Burp 复用 messageInfo 对象后取到别的流量；
        // 同时保留原对象引用，命中时用于在 Burp 流量上打高亮和备注
        final IHttpRequestResponse snapshot = new Snapshot(base);
        final IHttpRequestResponse original = base;
        pool.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    checkVul(snapshot, toolFlag, original);
                } catch (Throwable t) {
                    stdout.println("扫描异常：" + t);
                    t.printStackTrace(stderr);
                }
            }
        });
    }

    // ==================================================================
    // 核心检测逻辑
    // ==================================================================
    private void checkVul(IHttpRequestResponse base, int toolFlag, IHttpRequestResponse original) {
        // 总开关实时读取：任务在队列里排队期间被关闭也会立即失效，不用提交时的快照
        if (!cfg.enabled || base == null) {
            return;
        }
        final Config c = cfg;
        byte[] req = base.getRequest();
        byte[] origResp = base.getResponse();
        if (req == null || origResp == null || origResp.length == 0) {
            stdout.println("该数据包无响应，跳过");
            return;
        }

        IRequestInfo reqInfo = helpers.analyzeRequest(base);
        IResponseInfo respInfo = helpers.analyzeResponse(origResp);
        IHttpService service = base.getHttpService();
        URL url = reqInfo.getUrl();
        String host = service != null ? service.getHost() : url.getHost();
        int port = service != null ? service.getPort() : url.getPort();
        String urlText = url.toString();
        String path = url.getPath() == null ? "" : url.getPath();
        String method = reqInfo.getMethod();

        // ---- 范围过滤 ----
        if (!hostAllowed(host, urlText, c)) {
            return;
        }
        if (!portAllowed(port, c)) {
            return;
        }
        if (!methodAllowed(method, c.methods)) {
            return;
        }
        if (toolFlag != FORCE_SCAN && pathExcluded(path, c.excludePaths)) {
            stdout.println("排除路径（增删改/注册类接口），跳过：" + path);
            return;
        }
        if (toolFlag != FORCE_SCAN && c.skipStatic && isStaticPath(path, c.skipExts)) {
            stdout.println("静态资源类型，跳过：" + path);
            return;
        }
        if (c.skipBinary && looksBinary(req, reqInfo.getBodyOffset())) {
            return;
        }

        int bodyOffset = respInfo.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset > origResp.length) {
            bodyOffset = 0;
        }
        int origBodyLen = origResp.length - bodyOffset;
        if (origBodyLen > c.maxResponseKB * 1024) {
            stdout.println("响应体过大，跳过：" + origBodyLen + " bytes");
            return;
        }
        if (c.skipBinary && looksBinary(origResp, bodyOffset)) {
            stdout.println("响应内容为二进制，跳过：" + urlText);
            return;
        }

        // ---- Content-Type 判定 ----
        String respCT = headerValue(respInfo.getHeaders(), "content-type");
        String reqCT = headerValue(reqInfo.getHeaders(), "content-type");
        String respType = normalizeType(respCT);
        if (respType.length() == 0) {
            // 响应没写 Content-Type 时，用 Burp 自己推断的 MIME 兜底
            respType = burpMimeToType(respInfo.getStatedMimeType());
            if (respType.length() == 0) {
                respType = burpMimeToType(respInfo.getInferredMimeType());
            }
            if (respType.length() == 0 && c.allowMissingCT) {
                respType = "text/html";
            }
        }
        String reqType = normalizeType(reqCT);

        boolean respOk = matchesAny(respType, c.responseTypes);
        boolean reqOk = matchesAny(reqType, c.responseTypes);
        boolean extraOk = c.requestTypes.trim().length() == 0 || matchesAny(reqType, c.requestTypes);
        boolean ctPass;
        switch (c.ctMode) {
            case 1:
                ctPass = reqOk;                  // 只看请求 Content-Type
                break;
            case 2:
                ctPass = respOk || reqOk;        // 任一
                break;
            case 3:
                ctPass = respOk && reqOk;        // 两者
                break;
            default:
                ctPass = respOk;                 // 默认：响应（推荐）
                break;
        }
        if (!ctPass || !extraOk) {
            stdout.println("Content-Type 不匹配，跳过：" + urlText
                    + " | resp=" + respType + " req=" + reqType);
            return;
        }

        // ---- 取参数 ----
        List<IParameter> all = reqInfo.getParameters();
        List<IParameter> targets = new ArrayList<IParameter>();
        TreeSet<String> signatures = new TreeSet<String>();
        for (IParameter p : all) {
            byte type = p.getType();
            if (!typeAllowed(type, c)) {
                continue;
            }
            String name = p.getName();
            if (name == null || name.length() == 0 || skipParamName(name, c.skipParams)) {
                continue;
            }
            // 参数值偏移必须可用来做精确替换
            int s = p.getValueStart();
            int e = p.getValueEnd();
            if (s < 0 || e < s || e > req.length) {
                continue;
            }
            targets.add(p);
            signatures.add(name + ":" + type);
            if (targets.size() >= c.maxParams) {
                break;
            }
        }
        if (targets.isEmpty()) {
            stdout.println("无可用参数(url/body/json/cookie)，跳过：" + urlText);
            return;
        }

        // ---- 去重：MD5(不带参数的 URL + 参数名/位置 + 方法)，Set.add 原子操作避免竞态 ----
        String baseUrl = urlText.contains("?") ? urlText.substring(0, urlText.indexOf('?')) : urlText;
        String fingerprint = MD5(baseUrl + "+" + method + "+" + signatures.toString());
        stdout.println("MD5(\"" + baseUrl + "+" + method + "+" + signatures + "\") = " + fingerprint);
        if (!seen.add(fingerprint)) {
            if (toolFlag != FORCE_SCAN) {
                stdout.println("已扫描过，跳过：" + baseUrl
                        + "（右键 Send to xia XSS 可强制重扫；点「清空列表」可重置去重记录）");
                return;
            }
            // 右键发送：换新 id，保证同一请求可以重复扫描
            fingerprint = MD5(fingerprint + System.nanoTime());
            seen.add(fingerprint);
        }

        final String group = fingerprint;
        LogEntry entry = new LogEntry(seq.getAndIncrement(), toolFlag, base, urlText, method,
                respType.length() == 0 ? "(none)" : respType, origResp.length, targets.size(), group);
        log.add(entry);
        refreshTables();

        // ---- 逐参数 / 逐 payload 探测 ----
        boolean anyHit = false;
        int hitCount = 0;
        for (IParameter p : targets) {
            // 总开关实时生效：关闭后不再发起新的探测请求
            if (!cfg.enabled) {
                entry.state = "stopped";
                break;
            }
            String paramName = p.getName();
            byte type = p.getType();
            String originalValue = new String(req, p.getValueStart(),
                    p.getValueEnd() - p.getValueStart(), StandardCharsets.ISO_8859_1);
            List<Payload> payloads = buildPayloads(c, originalValue);

            for (Payload pl : payloads) {
                if (!cfg.enabled) {
                    break;
                }
                String finalValue = c.appendMode ? originalValue + pl.text : pl.text;
                byte[] newReq = replaceParameterValue(req, p, finalValue, c.encodePayload);
                if (newReq == null) {
                    continue;
                }
                long t1 = System.currentTimeMillis();
                IHttpRequestResponse attack = null;
                String error = null;
                try {
                    attack = callbacks.makeHttpRequest(service, newReq);
                } catch (Exception ex) {
                    error = String.valueOf(ex);
                }
                long cost = System.currentTimeMillis() - t1;

                int status = 0;
                String context = "";
                boolean hit = false;
                if (attack != null && attack.getResponse() != null) {
                    byte[] attackResp = attack.getResponse();
                    IResponseInfo ari = helpers.analyzeResponse(attackResp);
                    status = ari.getStatusCode();
                    byte[] tokenBytes = pl.token.getBytes(StandardCharsets.US_ASCII);
                    // 原始响应里本来就带这串随机字符 -> 判为误报
                    boolean inOriginal = indexOf(origResp, tokenBytes, 0, origResp.length) >= 0;
                    int attackBodyOff = ari.getBodyOffset();
                    if (attackBodyOff < 0 || attackBodyOff > attackResp.length) {
                        attackBodyOff = 0;
                    }
                    int inBody = indexOf(attackResp, tokenBytes, attackBodyOff, attackResp.length);
                    int inHeader = indexOf(attackResp, tokenBytes, 0, attackBodyOff);
                    boolean utf16Hit = false;
                    if (inBody < 0 && inHeader < 0) {
                        // 兼容 UTF-16 之类被插入 0x00 的编码
                        byte[] stripped = stripZeroBytes(attackResp);
                        utf16Hit = indexOf(stripped, tokenBytes, 0, stripped.length) >= 0;
                    }
                    hit = !inOriginal && (inBody >= 0 || inHeader >= 0 || utf16Hit);
                    if (hit) {
                        anyHit = true;
                        hitCount++;
                        if (utf16Hit) {
                            context = "UTF-16 / 含空字节编码";
                        } else if (inBody >= 0) {
                            context = analyzeContext(attackResp, inBody, pl.token);
                        } else {
                            context = "响应头（如 Location / Set-Cookie）";
                        }
                        stdout.println("✔ 反射命中：" + paramName + " | " + pl.token
                                + " | " + context + " | " + urlText);
                        // HaE 式标记：命中时在 Burp 原始流量上打高亮和备注，
                        // HTTP history 里可直接按高亮色过滤、按备注搜索定位
                        try {
                            if (original != null) {
                                original.setHighlight("cyan");
                                original.setComment("xia XSS ✔ " + paramName
                                        + " | " + pl.token + " | " + context);
                            }
                        } catch (Throwable ignore) {
                            // 原始对象不可标注（如右键选择的临时项）时忽略
                        }
                    }
                } else if (error == null) {
                    error = "无响应";
                }

                ProbeEntry pe = new ProbeEntry(seq.getAndIncrement(), group, paramName,
                        locationName(type), pl.text, pl.token, hit, context, status, cost,
                        error, attack == null ? null : new Snapshot(attack));
                probes.add(pe);
                refreshTables();

                if (c.delayMs > 0) {
                    try {
                        Thread.sleep(c.delayMs);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            entry.state = anyHit ? "run…… ✔" : "run……";
        }
        if (entry.state.equals("stopped")) {
            refreshTables();
            stdout.println("插件已关闭，扫描中止：" + urlText);
            return;
        }
        entry.state = anyHit ? "end! ✔ (" + hitCount + ")" : "end!";
        refreshTables();
        stdout.println("扫描完成：" + urlText + " | 参数=" + targets.size()
                + " | 探测=" + countProbes(group) + " | 命中=" + hitCount);
    }

    private int countProbes(String group) {
        int n = 0;
        for (ProbeEntry p : probes) {
            if (p.group.equals(group)) {
                n++;
            }
        }
        return n;
    }

    /** 内置探测 = 纯随机字符串；自定义语句用 %s / {RAND} 承载新的随机串 */
    private List<Payload> buildPayloads(Config c, String originalValue) {
        List<Payload> list = new ArrayList<Payload>();
        if (!c.customEnabled || c.keepProbe) {
            String t = randomToken(c.randomLen);
            list.add(new Payload(t, t));
        }
        if (c.customEnabled) {
            String[] lines = c.payloadText.split("\\r?\\n");
            for (String raw : lines) {
                String line = raw.trim();
                if (line.length() == 0 || line.startsWith("#")) {
                    continue;
                }
                String token = randomToken(c.randomLen);
                boolean hasPlaceholder = line.contains("%s") || line.contains("{RAND}")
                        || line.contains("{rand}");
                String text = line.replace("%s", token)
                        .replace("{RAND}", token)
                        .replace("{rand}", token)
                        .replace("{V}", originalValue);
                if (!hasPlaceholder) {
                    // 没写占位符时把随机串附在末尾，保证仍能判断反射（建议语句里显式写 %s）
                    text = text + token;
                }
                list.add(new Payload(text, token));
            }
        }
        if (list.isEmpty()) {
            String t = randomToken(c.randomLen);
            list.add(new Payload(t, t));
        }
        return list;
    }

    /** 纯随机小写字母+数字，不带任何可读前缀，避免影响回显判断 */
    private String randomToken(int len) {
        final String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * 用 Burp 给出的参数值偏移做字节级替换，比按字符串拼 body 稳得多，
     * 天然支持 url / form / json / xml / cookie，且不会破坏 JSON 结构。
     */
    private byte[] replaceParameterValue(byte[] req, IParameter p, String value, boolean encode) {
        int s = p.getValueStart();
        int e = p.getValueEnd();
        if (s < 0 || e < s || e > req.length) {
            return null;
        }
        byte type = p.getType();

        // 个别 Burp 版本对 JSON 参数返回的偏移会把双引号一起包进来，先剥掉
        boolean offsetsIncludeQuotes = (type == IParameter.PARAM_JSON)
                && e - s >= 2 && req[s] == '"' && req[e - 1] == '"';
        if (offsetsIncludeQuotes) {
            s++;
            e--;
        }
        boolean jsonValueQuoted = (s > 0 && req[s - 1] == '"')
                && (e < req.length && req[e] == '"');

        String encoded;
        switch (type) {
            case IParameter.PARAM_URL:
            case IParameter.PARAM_BODY:
            case IParameter.PARAM_COOKIE:
                encoded = encode ? formEncode(value) : value;
                break;
            case IParameter.PARAM_JSON:
                encoded = encode ? jsonEscape(value) : value;
                // 原值是数字 / 布尔时，替换成字符串要补上引号，否则 JSON 不合法
                if (encode && !offsetsIncludeQuotes && !jsonValueQuoted) {
                    encoded = "\"" + encoded + "\"";
                }
                break;
            case IParameter.PARAM_XML:
                encoded = encode ? xmlEscape(value) : value;
                break;
            default:
                encoded = value;
                break;
        }

        byte[] replacement = encoded.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[s + replacement.length + (req.length - e)];
        System.arraycopy(req, 0, out, 0, s);
        System.arraycopy(replacement, 0, out, s, replacement.length);
        System.arraycopy(req, e, out, s + replacement.length, req.length - e);
        return fixContentLength(out);
    }

    /** 参数值变长/变短后必须同步 Content-Length，否则服务端会截断或挂起 */
    private byte[] fixContentLength(byte[] req) {
        try {
            IRequestInfo info = helpers.analyzeRequest(req);
            int off = info.getBodyOffset();
            if (off >= req.length) {
                return req; // 无 body（典型 GET，URL 参数变化不影响 Content-Length）
            }
            byte[] body = Arrays.copyOfRange(req, off, req.length);
            List<String> headers = new ArrayList<String>(info.getHeaders());
            boolean chunked = false;
            boolean found = false;
            for (int i = 0; i < headers.size(); i++) {
                String lower = headers.get(i).toLowerCase(Locale.ROOT);
                if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
                    chunked = true;
                }
                if (lower.startsWith("content-length:")) {
                    headers.set(i, "Content-Length: " + body.length);
                    found = true;
                }
            }
            if (!found && !chunked) {
                headers.add("Content-Length: " + body.length);
            }
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception ex) {
            stdout.println("修正 Content-Length 失败：" + ex);
            return req;
        }
    }

    // ------------------------------------------------------------------
    // 工具方法
    // ------------------------------------------------------------------
    private static String formEncode(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        final char[] hex = "0123456789ABCDEF".toCharArray();
        for (byte b : bytes) {
            int v = b & 0xff;
            if ((v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z')
                    || (v >= '0' && v <= '9') || v == '-' || v == '.' || v == '_' || v == '~') {
                sb.append((char) v);
            } else {
                sb.append('%').append(hex[v >>> 4]).append(hex[v & 0xf]);
            }
        }
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    private static String xmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    private static String headerValue(List<String> headers, String name) {
        for (String h : headers) {
            int idx = h.indexOf(':');
            if (idx > 0 && h.substring(0, idx).trim().equalsIgnoreCase(name)) {
                return h.substring(idx + 1).trim();
            }
        }
        return "";
    }

    private static String normalizeType(String ct) {
        if (ct == null) {
            return "";
        }
        int i = ct.indexOf(';');
        return (i < 0 ? ct : ct.substring(0, i)).trim().toLowerCase(Locale.ROOT);
    }

    private static String burpMimeToType(String mime) {
        if (mime == null) {
            return "";
        }
        String m = mime.trim().toUpperCase(Locale.ROOT);
        if (m.contains("HTML")) {
            return "text/html";
        }
        if (m.contains("SCRIPT") || m.contains("JS")) {
            return "text/javascript";
        }
        if (m.contains("XML")) {
            return "text/xml";
        }
        if (m.contains("PLAIN")) {
            return "text/plain";
        }
        if (m.contains("JSON")) {
            return "application/json";
        }
        return "";
    }

    private static boolean matchesAny(String value, String patterns) {
        if (value == null || value.length() == 0) {
            return false;
        }
        for (String raw : patterns.split(",")) {
            String p = normalizeType(raw);
            if (p.length() == 0) {
                continue;
            }
            if (p.indexOf('*') >= 0 || p.indexOf('?') >= 0) {
                StringBuilder regex = new StringBuilder();
                for (char ch : p.toCharArray()) {
                    if (ch == '*') {
                        regex.append(".*");
                    } else if (ch == '?') {
                        regex.append('.');
                    } else {
                        regex.append(Pattern.quote(String.valueOf(ch)));
                    }
                }
                if (Pattern.matches(regex.toString(), value)) {
                    return true;
                }
            } else if (value.equals(p)) {
                return true;
            }
        }
        return false;
    }

    private boolean hostAllowed(String host, String url, Config c) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        String u = url == null ? "" : url.toLowerCase(Locale.ROOT);
        for (String raw : c.excludeHosts.split(",")) {
            String p = raw.trim().toLowerCase(Locale.ROOT);
            if (p.length() > 0 && hostMatches(h, u, p)) {
                return false;
            }
        }
        if (!c.whitelistOn || c.whitelist.trim().length() == 0) {
            return true;
        }
        for (String raw : c.whitelist.split(",")) {
            String p = raw.trim().toLowerCase(Locale.ROOT);
            if (p.length() > 0 && hostMatches(h, u, p)) {
                stdout.println("白名单 URL：" + url);
                return true;
            }
        }
        stdout.println("不在白名单，跳过：" + url);
        return false;
    }

    private static boolean hostMatches(String host, String url, String pattern) {
        if (pattern.indexOf('*') >= 0) {
            String regex = Pattern.quote(pattern).replace("\\*", ".*");
            return Pattern.matches(regex, host) || Pattern.matches(regex, url);
        }
        return host.equals(pattern) || host.endsWith("." + pattern) || url.contains(pattern);
    }

    private static boolean portAllowed(int port, Config c) {
        if (c.denyPorts.trim().length() > 0 && intListContains(c.denyPorts, port)) {
            return false;
        }
        return c.allowPorts.trim().length() == 0 || intListContains(c.allowPorts, port);
    }

    private static boolean intListContains(String list, int value) {
        for (String s : list.split(",")) {
            try {
                if (Integer.parseInt(s.trim()) == value) {
                    return true;
                }
            } catch (NumberFormatException ignored) {
                // 忽略非法端口
            }
        }
        return false;
    }

    private static boolean methodAllowed(String method, String methods) {
        if (methods == null || methods.trim().length() == 0) {
            return true;
        }
        for (String m : methods.split(",")) {
            if (m.trim().equalsIgnoreCase(method)) {
                return true;
            }
        }
        return false;
    }

    private static boolean skipParamName(String name, String skipList) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String s : skipList.split(",")) {
            String p = s.trim().toLowerCase(Locale.ROOT);
            if (p.length() > 0 && n.contains(p)) {
                return true;
            }
        }
        return false;
    }

    /** URL 后缀是否命中可自定义的资源类型排除列表（js/ts 等前端与静态资源） */
    private static boolean isStaticPath(String path, String extList) {
        String p = path.toLowerCase(Locale.ROOT);
        int dot = p.lastIndexOf('.');
        int slash = p.lastIndexOf('/');
        if (dot < 0 || dot < slash) {
            return false;
        }
        String ext = p.substring(dot + 1);
        return extListContains(extList, ext);
    }

    private static boolean extListContains(String extList, String ext) {
        for (String raw : extList.split(",")) {
            if (raw.trim().toLowerCase(Locale.ROOT).equals(ext)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 排除增删改 / 注册等添加或修改性接口：
     * 关键词里带 / 时对整个 path 做 contains 匹配（支持写 /api/user/add 这种精确路径）；
     * 否则按 / _ - . 分段后精确匹配，避免 addressbook 之类误伤。
     */
    private static boolean pathExcluded(String path, String keywords) {
        String p = path.toLowerCase(Locale.ROOT);
        if (p.length() == 0) {
            return false;
        }
        for (String raw : keywords.split(",")) {
            String k = raw.trim().toLowerCase(Locale.ROOT);
            if (k.length() == 0) {
                continue;
            }
            if (k.indexOf('/') >= 0) {
                if (p.contains(k)) {
                    return true;
                }
            } else {
                for (String token : p.split("[/_\\-.0-9]")) {
                    if (token.equals(k)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** 粗略判断二进制内容（有 NUL 字节）；UTF-8 中文不会被误判 */
    private static boolean looksBinary(byte[] data, int offset) {
        int start = Math.max(0, offset);
        int end = Math.min(data.length, start + 512);
        int nul = 0;
        for (int i = start; i < end; i++) {
            if (data[i] == 0) {
                nul++;
            }
        }
        return nul >= 2;
    }

    private static boolean typeAllowed(byte type, Config c) {
        return type == IParameter.PARAM_URL
                || type == IParameter.PARAM_BODY
                || type == IParameter.PARAM_JSON
                || type == IParameter.PARAM_XML
                || (c.testCookie && type == IParameter.PARAM_COOKIE);
    }

    private static String locationName(byte type) {
        switch (type) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "BODY";
            case IParameter.PARAM_JSON:
                return "JSON";
            case IParameter.PARAM_XML:
                return "XML";
            case IParameter.PARAM_COOKIE:
                return "COOKIE";
            default:
                return "OTHER(" + type + ")";
        }
    }

    /** 字节级查找，避免 helpers.bytesToString 的编码问题丢字符 */
    private static int indexOf(byte[] hay, byte[] needle, int from, int to) {
        if (needle.length == 0 || to > hay.length) {
            return -1;
        }
        int last = to - needle.length;
        outer:
        for (int i = Math.max(0, from); i <= last; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static byte[] stripZeroBytes(byte[] data) {
        byte[] out = new byte[data.length];
        int n = 0;
        for (byte b : data) {
            if (b != 0) {
                out[n++] = b;
            }
        }
        return Arrays.copyOf(out, n);
    }

    /** 判断随机串落在 HTML 的什么位置，辅助人工判断能不能真的执行 */
    private static String analyzeContext(byte[] resp, int hitIndex, String token) {
        int start = Math.max(0, hitIndex - 2048);
        int end = Math.min(resp.length, hitIndex + token.length() + 256);
        if (start >= end) {
            return "响应体";
        }
        String body = new String(resp, start, end - start, StandardCharsets.ISO_8859_1);
        int idx = body.indexOf(token);
        if (idx < 0) {
            return "响应体";
        }
        String before = body.substring(0, idx).toLowerCase(Locale.ROOT);
        if (before.lastIndexOf("<!--") > before.lastIndexOf("-->")) {
            return "HTML 注释内";
        }
        if (before.lastIndexOf("<script") > before.lastIndexOf("</script")) {
            return "<script> 内";
        }
        if (before.lastIndexOf("<style") > before.lastIndexOf("</style")) {
            return "<style> 内";
        }
        int lt = before.lastIndexOf('<');
        int gt = before.lastIndexOf('>');
        if (lt > gt) {
            String tag = before.substring(lt);
            if (countChar(tag, '\'') % 2 == 1 || countChar(tag, '"') % 2 == 1) {
                return "标签属性（引号内）";
            }
            return "标签属性（未加引号）";
        }
        return "HTML 文本 / 正文";
    }

    private static int countChar(String s, char ch) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == ch) {
                n++;
            }
        }
        return n;
    }

    public static String MD5(String key) {
        final char[] hex = "0123456789ABCDEF".toCharArray();
        try {
            byte[] input = key.getBytes(StandardCharsets.UTF_8);
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input);
            char[] out = new char[digest.length * 2];
            for (int i = 0, k = 0; i < digest.length; i++) {
                int v = digest[i] & 0xff;
                out[k++] = hex[v >>> 4];
                out[k++] = hex[v & 0xf];
            }
            return new String(out);
        } catch (Exception e) {
            return String.valueOf(System.nanoTime());
        }
    }

    // ==================================================================
    // ITab / IMessageEditorController
    // ==================================================================
    @Override
    public String getTabCaption() {
        return EXT_NAME;
    }

    @Override
    public Component getUiComponent() {
        return uiRoot;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getHttpService();
    }

    // ==================================================================
    // 表格模型（主表：原始请求；明细表：每次探测）
    // ==================================================================
    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 8;
    }

    @Override
    public String getColumnName(int col) {
        switch (col) {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "URL";
            case 3:
                return "方法";
            case 4:
                return "响应 Content-Type";
            case 5:
                return "返回包长度";
            case 6:
                return "参数数";
            case 7:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return Object.class;
    }

    @Override
    public Object getValueAt(int row, int col) {
        if (row < 0 || row >= log.size()) {
            return "";
        }
        LogEntry e = log.get(row);
        switch (col) {
            case 0:
                return e.id;
            case 1:
                return callbacks.getToolName(e.tool);
            case 2:
                return e.url;
            case 3:
                return e.method;
            case 4:
                return e.respType;
            case 5:
                return e.respLen;
            case 6:
                return e.paramCount;
            case 7:
                return e.state;
            default:
                return "";
        }
    }

    private class DetailModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return shown.size();
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public String getColumnName(int col) {
            switch (col) {
                case 0:
                    return "#";
                case 1:
                    return "参数";
                case 2:
                    return "位置";
                case 3:
                    return "Payload / 随机字符";
                case 4:
                    return "命中";
                case 5:
                    return "反射上下文";
                case 6:
                    return "响应码";
                case 7:
                    return "用时(ms)";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int col) {
            return Object.class;
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= shown.size()) {
                return "";
            }
            ProbeEntry e = shown.get(row);
            switch (col) {
                case 0:
                    return e.id;
                case 1:
                    return e.param;
                case 2:
                    return e.location;
                case 3:
                    return e.payload;
                case 4:
                    return e.error != null ? "ERR" : (e.hit ? "✔" : "");
                case 5:
                    return e.error != null ? e.error : e.context;
                case 6:
                    return e.status;
                case 7:
                    return e.cost;
                default:
                    return "";
            }
        }
    }

    private class MainTable extends JTable {
        MainTable(TableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row >= 0 && row < log.size()) {
                LogEntry e = log.get(row);
                selectedMd5 = e.group;
                selectedRow = row;
                rebuildShown();
                detailModel.fireTableDataChanged();
                requestViewer.setMessage(e.rr.getRequest(), true);
                responseViewer.setMessage(e.rr.getResponse(), false);
                currentlyDisplayedItem = e.rr;
                //点击即复制URL：HTTP history 中 Ctrl+F 粘贴可快速定位原始请求
                copyToClipboard(e.url);
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class DetailTable extends JTable {
        DetailTable(TableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row >= 0 && row < shown.size()) {
                ProbeEntry e = shown.get(row);
                if (e.rr != null) {
                    requestViewer.setMessage(e.rr.getRequest(), true);
                    responseViewer.setMessage(e.rr.getResponse(), false);
                    currentlyDisplayedItem = e.rr;
                    // 随机字符自动填入下方请求/响应包自带的搜索框，直接高亮定位
                    setEditorSearch(requestViewer, e.token);
                    setEditorSearch(responseViewer, e.token);
                }
                //点击即复制随机字符：需要跨到 HTTP history 搜索时可直接粘贴
                copyToClipboard(e.token);
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // 复制到剪贴板 + 右键复制菜单（Burp API 不暴露搜索栏，用复制粘贴定位）
    //

    /**
     * 旧版 IMessageEditor 接口没有暴露搜索框 API（新版 Montoya 的编辑器有
     * setSearchExpression）。两级策略：
     *   1. 反射调用内部实现对象的 setSearchExpression；
     *   2. 反射失败时遍历编辑器组件树，找到搜索框 JTextField 直接 setText（参考 HaE 的
     *      自动定位思路：让反射点在编辑器里直接高亮，而不是只复制到剪贴板）。
     */
    private void setEditorSearch(IMessageEditor editor, String expression) {
        if (editor == null || expression == null || expression.length() == 0) {
            return;
        }
        try {
            Method m = editor.getClass().getMethod("setSearchExpression", String.class);
            m.setAccessible(true);
            m.invoke(editor, expression);
            return;
        } catch (Throwable ignore) {
            // 内部实现无该方法，走组件树查找
        }
        try {
            JTextField field = findSearchField(editor.getComponent());
            if (field != null) {
                // setText 会触发编辑器搜索框的文档监听，命中处随之高亮
                field.setText(expression);
            }
        } catch (Throwable ignore) {
            // 组件树结构变化时忽略，剪贴板兜底仍可用
        }
    }

    /** 在消息编辑器的组件树里找搜索框：名字/提示含 search 的优先，否则取遍历到最后一个 JTextField */
    private JTextField findSearchField(Component c) {
        JTextField named = findFieldRec(c, true);
        if (named != null) {
            return named;
        }
        return findFieldRec(c, false);
    }

    /**
     * namedOnly=true：只返回名字/提示明确含 search 的字段；
     * namedOnly=false：返回深度优先遍历中最后一个 JTextField（Burp 编辑器搜索框在布局尾部）。
     */
    private JTextField findFieldRec(Component c, boolean namedOnly) {
        if (c instanceof JTextField) {
            JTextField f = (JTextField) c;
            if (namedOnly) {
                String name = f.getName();
                String tip = f.getToolTipText();
                if ((name != null && name.toLowerCase(Locale.ROOT).contains("search"))
                        || (tip != null && tip.toLowerCase(Locale.ROOT).contains("search"))) {
                    return f;
                }
            } else {
                return f;
            }
        }
        if (c instanceof Container) {
            JTextField last = null;
            for (Component child : ((Container) c).getComponents()) {
                JTextField hit = findFieldRec(child, namedOnly);
                if (hit != null) {
                    if (namedOnly) {
                        return hit;
                    }
                    last = hit;
                }
            }
            return last;
        }
        return null;
    }

    private void copyToClipboard(String text) {
        if (text == null || text.length() == 0) {
            return;
        }
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
            String show = text.length() > 60 ? text.substring(0, 60) + "..." : text;
            setStatus("已复制：" + show + "  ← HTTP history 中 Ctrl+F 粘贴可快速定位");
        } catch (Exception ex) {
            stdout.println("复制到剪贴板失败：" + ex);
        }
    }

    private void setStatus(String text) {
        if (lblStat != null) {
            lblStat.setText(text);
        }
    }

    private JMenuItem copyItem(String label, final Provider provider) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyToClipboard(provider.get());
            }
        });
        return mi;
    }

    private interface Provider {
        String get();
    }

    /** 主表右键：复制 URL */
    private JPopupMenu mainPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        menu.add(copyItem("复制 URL", new Provider() {
            @Override
            public String get() {
                int row = logTable.getSelectedRow();
                return (row >= 0 && row < log.size()) ? log.get(row).url : null;
            }
        }));
        return menu;
    }

    /** 明细表右键：复制随机字符 / payload / 参数名 / URL */
    private JPopupMenu detailPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        menu.add(copyItem("复制随机字符（BP 搜索定位用）", new Provider() {
            @Override
            public String get() {
                ProbeEntry e = selectedProbe();
                return e == null ? null : e.token;
            }
        }));
        menu.add(copyItem("复制 Payload", new Provider() {
            @Override
            public String get() {
                ProbeEntry e = selectedProbe();
                return e == null ? null : e.payload;
            }
        }));
        menu.add(copyItem("复制参数名", new Provider() {
            @Override
            public String get() {
                ProbeEntry e = selectedProbe();
                return e == null ? null : e.param;
            }
        }));
        menu.add(copyItem("复制 URL", new Provider() {
            @Override
            public String get() {
                ProbeEntry e = selectedProbe();
                if (e == null || e.rr == null) {
                    return null;
                }
                try {
                    return helpers.analyzeRequest(e.rr).getUrl().toString();
                } catch (Exception ex) {
                    return null;
                }
            }
        }));
        return menu;
    }

    private ProbeEntry selectedProbe() {
        int row = detailTable.getSelectedRow();
        return (row >= 0 && row < shown.size()) ? shown.get(row) : null;
    }

    private void rebuildShown() {
        shown.clear();
        String group = selectedMd5;
        if (group == null) {
            return;
        }
        for (ProbeEntry p : probes) {
            if (p.group.equals(group)) {
                shown.add(p);
            }
        }
    }

    private void refreshTables() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                rebuildShown();
                fireTableDataChanged();
                detailModel.fireTableDataChanged();
                if (lblStat != null) {
                    int hits = 0;
                    for (ProbeEntry p : probes) {
                        if (p.hit) {
                            hits++;
                        }
                    }
                    int running = 0;
                    for (LogEntry e : log) {
                        if (e.state.startsWith("run")) {
                            running++;
                        }
                    }
                    lblStat.setText("请求 " + log.size() + " | 探测 " + probes.size()
                            + " | 命中 " + hits + " | 扫描中 " + running);
                }
                if (selectedRow >= 0 && selectedRow < log.size() && logTable != null) {
                    try {
                        logTable.setRowSelectionInterval(selectedRow, selectedRow);
                    } catch (Exception ignored) {
                        // 表格模型刷新过程中偶发越界，忽略
                    }
                }
            }
        });
    }

    // ==================================================================
    // 数据结构
    // ==================================================================
    private static class Config {
        boolean enabled = true;
        boolean monitorProxy = true;
        boolean monitorRepeater = false;
        boolean monitorOther = false;
        boolean testCookie = false;
        boolean skipStatic = true;
        boolean skipBinary = true;
        boolean encodePayload = true;
        boolean appendMode = false;
        boolean allowMissingCT = false;
        boolean whitelistOn = false;
        boolean customEnabled = false;
        boolean keepProbe = true;
        String whitelist = "";
        /** 默认排除教育、政府等敏感单位域名，避免误测 */
        String excludeHosts = "edu.cn,gov.cn";
        String allowPorts = "";
        String denyPorts = "";
        String methods = "";
        String responseTypes = DEFAULT_TYPES;
        String requestTypes = "";
        String skipParams = DEFAULT_SKIP_PARAMS;
        String excludePaths = DEFAULT_EXCLUDE_PATHS;
        String skipExts = DEFAULT_SKIP_EXTS;
        String payloadText = DEFAULT_PAYLOAD_TEXT;
        int ctMode = 0; // 0响应 1请求 2任一 3两者
        int randomLen = 10;
        int maxParams = 30;
        int maxResponseKB = 512;
        int threads = 4;
        int delayMs = 0;

        static Config defaults() {
            return new Config();
        }
    }

    private static class Payload {
        final String text;
        final String token;

        Payload(String text, String token) {
            this.text = text;
            this.token = token;
        }
    }

    private static class LogEntry {
        final int id;
        final int tool;
        final IHttpRequestResponse rr;
        final String url;
        final String method;
        final String respType;
        final int respLen;
        final int paramCount;
        final String group;
        volatile String state = "run……";

        LogEntry(int id, int tool, IHttpRequestResponse rr, String url, String method,
                 String respType, int respLen, int paramCount, String group) {
            this.id = id;
            this.tool = tool;
            this.rr = rr;
            this.url = url;
            this.method = method;
            this.respType = respType;
            this.respLen = respLen;
            this.paramCount = paramCount;
            this.group = group;
        }
    }

    private static class ProbeEntry {
        final int id;
        final String group;
        final String param;
        final String location;
        final String payload;
        final String token;
        final boolean hit;
        final String context;
        final int status;
        final long cost;
        final String error;
        final IHttpRequestResponse rr;

        ProbeEntry(int id, String group, String param, String location, String payload,
                   String token, boolean hit, String context, int status, long cost,
                   String error, IHttpRequestResponse rr) {
            this.id = id;
            this.group = group;
            this.param = param;
            this.location = location;
            this.payload = payload;
            this.token = token;
            this.hit = hit;
            this.context = context;
            this.status = status;
            this.cost = cost;
            this.error = error;
            this.rr = rr;
        }
    }

    /** 轻量内存快照：把 Burp 传来的 messageInfo 复制下来，避免对象复用 / 写临时文件 */
    private static class Snapshot implements IHttpRequestResponse {
        private byte[] request;
        private byte[] response;
        private String comment;
        private String highlight;
        private IHttpService service;

        Snapshot(IHttpRequestResponse src) {
            this.request = src.getRequest();
            this.response = src.getResponse();
            this.service = src.getHttpService();
            this.comment = src.getComment();
            this.highlight = src.getHighlight();
        }

        @Override
        public byte[] getRequest() {
            return request;
        }

        @Override
        public void setRequest(byte[] message) {
            this.request = message;
        }

        @Override
        public byte[] getResponse() {
            return response;
        }

        @Override
        public void setResponse(byte[] message) {
            this.response = message;
        }

        @Override
        public String getComment() {
            return comment;
        }

        @Override
        public void setComment(String comment) {
            this.comment = comment;
        }

        @Override
        public String getHighlight() {
            return highlight;
        }

        @Override
        public void setHighlight(String color) {
            this.highlight = color;
        }

        @Override
        public IHttpService getHttpService() {
            return service;
        }

        @Override
        public void setHttpService(IHttpService httpService) {
            this.service = httpService;
        }
    }
}
