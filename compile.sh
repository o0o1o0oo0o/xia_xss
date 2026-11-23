#!/bin/sh
# 编译 xia XSS 插件并打包为可加载的 jar
# 用法: ./compile.sh <burp的jar路径>
#   例: ./compile.sh /Applications/Burp\ Suite\ Professional.app/Contents/Resources/app/burpsuite_pro.jar
#   例: ./compile.sh /tmp/burp-extender-api-2.3.jar   # 旧版API jar亦可
#
# 若不带参数，尝试使用 maven central 的 burp-extender-api-2.3.jar

set -e
cd "$(dirname "$0")"

API_JAR="$1"
if [ -z "$API_JAR" ]; then
    API_JAR="/tmp/burp-extender-api-2.3.jar"
    if [ ! -f "$API_JAR" ]; then
        echo "下载 burp-extender-api-2.3.jar ..."
        curl -s -o "$API_JAR" "https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar"
    fi
fi

echo "使用 classpath: $API_JAR"
rm -rf out
mkdir -p out
javac -encoding UTF-8 -cp "$API_JAR" -d out BurpExtender.java
jar -cf xia_xss.jar -C out burp
echo "完成: xia_xss.jar （在 Burp Extender -> Add 中加载）"
