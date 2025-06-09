import base64
import urllib.parse
import requests
import sys
import json
import os
import re
import argparse

def get_content_from_url(url):
    """从指定URL获取内容"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"从URL获取内容失败: {e}", file=sys.stderr)
        return None

def decode_base64_content(content):
    """对整个内容进行base64解码"""
    try:
        # 填充base64数据（如果需要）
        content += b'=' * (-len(content) % 4)
        return base64.b64decode(content).decode('utf-8')
    except Exception as e:
        print(f"Base64解码失败: {e}", file=sys.stderr)
        return None

def parse_ss_uri(ss_line):
    """核心解析函数：确保精确处理凭据部分"""
    if not ss_line.startswith("ss://"):
        return None

    try:
        # 移除ss://前缀
        uri = ss_line[5:]

        # 1. 提取并解码标签部分
        tag = ""
        if "#" in uri:
            uri, tag = uri.split("#", 1)
            tag = urllib.parse.unquote(tag.strip())

        # 2. 提取凭据部分（在@之前的部分）
        cred_base64 = ""
        if "@" in uri:
            cred_base64, server_full = uri.split("@", 1)
        else:
            server_full = uri

        # 3. 精确解码凭据部分（方法:密码）
        method = ""
        password = ""

        # 处理凭据部分的Base64解码
        if cred_base64:
            try:
                # 尝试Base64解码 - 处理填充问题
                padding = '=' * (-len(cred_base64) % 4)
                cred_data = base64.b64decode(cred_base64 + padding)
                decoded_cred = cred_data.decode('utf-8', errors='replace')

                # 在第一个冒号处分割方法名和密码
                if ":" in decoded_cred:
                    method, password = decoded_cred.split(":", 1)
                else:
                    method = decoded_cred
            except Exception as e:
                # 尝试直接解析凭据
                if ":" in cred_base64:
                    method, password = cred_base64.split(":", 1)
                else:
                    method = cred_base64

        # 4. 提取服务器、端口和插件信息
        server = ""
        port = None
        plugin = None
        plugin_opts = None

        # 分离服务器信息和插件参数
        if "?" in server_full:
            server_info, plugin_info = server_full.split("?", 1)
            # 只取plugin参数部分
            if "&" in plugin_info:
                plugin_info = plugin_info.split("&", 1)[0]
            if "#" in plugin_info:
                plugin_info = plugin_info.split("#", 1)[0]

            # 解析插件参数
            if plugin_info.startswith("plugin="):
                plugin_full = plugin_info[7:]
                plugin_full = urllib.parse.unquote(plugin_full)

                # 分割插件名和选项
                if ";" in plugin_full:
                    plugin, plugin_opts = plugin_full.split(";", 1)
                else:
                    plugin = plugin_full
        else:
            server_info = server_full

        # 从服务器部分提取主机和端口
        if "/" in server_info:
            server_info = server_info.split("/")[0]

        # 提取主机和端口
        if ":" in server_info:
            # 处理IPv6地址格式
            if "]" in server_info:
                server_end = server_info.index("]")
                server = server_info[1:server_end]
                port_start = server_end + 2
                port_str = server_info[port_start:]
            else:
                server, port_str = server_info.split(":", 1)

            # 尝试提取数字端口
            try:
                port_str = port_str.split("?")[0].split("&")[0].split("#")[0]
                port = int(port_str)
            except ValueError:
                port = None
        else:
            server = server_info

        # 5. 检查并替换simple-obfs为obfs-local
        if plugin == "simple-obfs":
            plugin = "obfs-local"

        # 6. 构建结果对象
        result = {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "method": method,
            "password": password
        }

        if plugin:
            result["plugin"] = plugin
        if plugin_opts:
            result["plugin_opts"] = plugin_opts

        return result

    except Exception as e:
        print(f"解析错误: {e}", file=sys.stderr)
        print(f"问题行: {ss_line}", file=sys.stderr)
        return None

def process_subscription(source):
    """处理订阅源（可以是URL或文件路径）"""
    # 确定输入源是URL还是文件
    if source.startswith("http://") or source.startswith("https://"):
        print(f"正在获取订阅源: {source}", file=sys.stderr)
        content = get_content_from_url(source)
        if content is None:
            print(f"获取订阅源失败: {source}", file=sys.stderr)
            return []
    else:
        print(f"正在读取订阅文件: {source}", file=sys.stderr)
        try:
            with open(source, 'rb') as f:
                content = f.read()
        except Exception as e:
            print(f"读取文件失败: {e}", file=sys.stderr)
            return []

    # 第一次解码：对整个内容进行base64解码
    decoded_content = decode_base64_content(content)
    if decoded_content is None:
        print(f"解码订阅源失败: {source}", file=sys.stderr)
        return []

    lines = decoded_content.splitlines()

    # 处理每一行
    results = []
    for line in lines:
        line = line.strip()
        if line and line.startswith("ss://"):
            parsed = parse_ss_uri(line)
            if parsed:
                results.append(parsed)

    print(f"成功解析 {len(results)} 个配置", file=sys.stderr)
    return results

def process_multiple_subscriptions(sources):
    """处理多个订阅源，合并结果"""
    all_configurations = []
    for source in sources:
        configs = process_subscription(source)
        if configs:
            all_configurations.extend(configs)

    if not all_configurations:
        print("未找到任何有效配置", file=sys.stderr)
        sys.exit(1)

    # 去重 - 根据tag去重
    unique_configs = {}
    for config in all_configurations:
        tag = config.get("tag", "")
        if tag:  # 只保留唯一tag的配置
            unique_configs[tag] = config
        else:  # 没有tag的配置直接保留
            unique_configs[len(unique_configs)] = config

    return list(unique_configs.values())

def extract_outbounds(configurations, keywords=None, exclude=False):
    """提取特定的tag值，支持过滤和排除"""
    outbounds = []

    for config in configurations:
        tag = config.get("tag", "")
        if not tag:
            continue

        tag_lower = tag.lower()

        # 是否排除匹配项
        if keywords:
            matches = any(keyword in tag_lower for keyword in keywords)
            if exclude and matches:
                continue
            if not exclude and not matches:
                continue

        outbounds.append(f'"{tag}"')

    return ",\n".join(outbounds)

def format_configurations(configurations):
    """格式化配置对象列表 - 修复plugin_opts引号问题"""
    formatted = []
    for i, config in enumerate(configurations):
        # 创建配置对象的深拷贝
        cfg_copy = config.copy()

        # 生成JSON字符串 - 使用json.dumps确保正确转义
        cfg_str = json.dumps(cfg_copy, ensure_ascii=False, indent=2)

        # 如果是最后一个配置，不加逗号
        if i < len(configurations) - 1:
            cfg_str += ","

        formatted.append(cfg_str)

    return "\n".join(formatted)

def get_template_content(template_source):
    """获取模板内容，支持URL或文件路径"""
    if template_source.startswith("http://") or template_source.startswith("https://"):
        print(f"正在获取模板URL: {template_source}", file=sys.stderr)
        try:
            content = get_content_from_url(template_source)
            return content.decode('utf-8') if content else None
        except Exception as e:
            print(f"获取模板内容失败: {e}", file=sys.stderr)
            return None
    else:
        print(f"正在读取模板文件: {template_source}", file=sys.stderr)
        try:
            with open(template_source, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"读取模板文件失败: {e}", file=sys.stderr)
            return None

def process_template(template_source, configurations):
    """处理模板内容，替换占位符"""
    # 获取模板内容
    template_content = get_template_content(template_source)
    if template_content is None:
        print(f"无法获取模板内容", file=sys.stderr)
        return None

    # 定义关键词列表（小写）
    hk_keywords = ['香港', '港', 'hk', 'hong kong', 'hongkong', 'hkong', 'h.k', 'h k']
    sg_keywords = ['新加坡', '狮', 'singapore', 'sg', '星洲', '星国', '新加', '新']
    tw_keywords = ['tw', 'taiwan', '台湾', '台','臺灣', '新北', '彰化']
    us_keywords = ['us', 'u s', 'united states', '美国', '美', '波特兰', '达拉斯', '俄勒冈', '凤凰城', '费利蒙', '硅谷', '拉斯维加斯', '洛杉矶', '圣何塞', '圣克拉拉', '西雅图', '芝加哥']
    jp_keywords = ['jp','j p', '日','日本', 'japan', '东京', '大阪', '埼玉']


    # 提取所有tag值（带双引号）
    all_tags = extract_outbounds(configurations)

    # 过滤tag值
    hk_tags = extract_outbounds(configurations, hk_keywords)
    not_hk_tags = extract_outbounds(configurations, hk_keywords, exclude=True)
    sg_tags = extract_outbounds(configurations, sg_keywords)
    tw_tags = extract_outbounds(configurations, tw_keywords)
    us_tags = extract_outbounds(configurations, us_keywords)
    jp_tags = extract_outbounds(configurations, jp_keywords)

    # 格式化配置对象列表 - 修复引号问题
    configs_formatted = format_configurations(configurations)

    # 替换占位符
    result = template_content
    result = result.replace("{sub_outbounds}", all_tags)
    result = result.replace("{sub_outbounds_HK}", hk_tags)
    result = result.replace("{sub_outbounds_!HK}", not_hk_tags)
    result = result.replace("{sub_outbounds_SG}", sg_tags)
    result = result.replace("{sub_outbounds_TW}", tw_tags)
    result = result.replace("{sub_outbounds_US}", us_tags)
    result = result.replace("{sub_outbounds_JP}", jp_tags)
    result = result.replace("{sub_outbounds_ALL}", configs_formatted)

    return result

def save_to_file(content, filename="config.json"):
    """将内容保存到文件"""
    if content is None:
        print("没有内容可以保存", file=sys.stderr)
        return False

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"配置文件已保存为: {filename}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"保存文件失败: {e}", file=sys.stderr)
        return False

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="处理Shadowsocks订阅")
    parser.add_argument('template', help="模板源（文件路径或URL）")
    parser.add_argument('subscriptions', nargs='+', help="一个或多个订阅源（文件路径或URL）")
    parser.add_argument('-o', '--output', default="config.json", help="输出文件名（默认为config.json）")
    return parser.parse_args()

# 使用示例
if __name__ == "__main__":
    args = parse_args()

    # 处理多个订阅源
    configurations = process_multiple_subscriptions(args.subscriptions)

    # 处理模板
    final_result = process_template(args.template, configurations)

    # 保存结果
    if final_result is not None:
        save_to_file(final_result, args.output)
        print("处理完成！", file=sys.stderr)
    else:
        print("处理失败！", file=sys.stderr)
        sys.exit(1)
