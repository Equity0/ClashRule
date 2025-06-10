import argparse
import base64
import re
import urllib.parse
import requests
import json 

# 定义关键词数组
default_exclude_keywords = ['traffic', 'expire', '流量', '剩余', '天数', '到期', '年', '月']
hk_keywords = ['香港', '港', 'hk', 'hong kong', 'hongkong', 'hkong']
sg_keywords = ['新加坡', '狮', 'singapore', 'sg', '星洲', '星国']
tw_keywords = ['tw', 'taiwan', '台湾', '台','臺灣', '新北', '彰化']
jp_keywords = ['jp','j p', '日','日本', 'japan', '东京', '大阪', '埼玉']
jp_exclude_keywords = ['日用', '尼日']
us_keywords = ['us', 'u s', 'united states', '美国', '美', '波特兰', '达拉斯', '俄勒冈', '凤凰城', '费利蒙', '硅谷', '拉斯维加斯', '洛杉矶', '圣何塞', '圣克拉拉', '西雅图', '芝加哥']

def get_content(source):
    """获取本地文件或URL内容"""
    if source.startswith(('http://', 'https://')):
        try:
            response = requests.get(source)
            response.raise_for_status()
            return response.content
        except Exception as e:
            raise ValueError(f"获取URL内容失败: {str(e)}")
    else:
        try:
            with open(source, 'rb') as f:
                return f.read()
        except Exception as e:
            raise ValueError(f"读取本地文件失败: {str(e)}")

def parse_ss_url(ss_line):
    """解析ss链接行，返回结构化数据"""
    # 去除可能的前后空格
    ss_line = ss_line.strip()
    if not ss_line.startswith('ss://'):
        return None

    # 正则匹配两种格式
    pattern = r'^ss://([^@]+)@([^:]+):(\d+)(?:/\?([^#]+))?#(.*)$'
    match = re.match(pattern, ss_line)
    if not match:
        return None

    auth_encoded, hostname, port, plugin_encoded, name_encoded = match.groups()
    
    # 解码name（直接使用urllib.parse.unquote，无额外处理）
    name = urllib.parse.unquote(name_encoded)
    
    # 解码auth
    try:
        auth = base64.urlsafe_b64decode(auth_encoded + '=' * (-len(auth_encoded) % 4)).decode('utf-8')
    except:
        return None
    if ':' not in auth:
        return None
    method, password = auth.split(':', 1)
    
    # 处理plugin
    plugin_info = {}
    if plugin_encoded:
        plugin_decoded = urllib.parse.unquote(plugin_encoded)
        plugin_parts = plugin_decoded.split(';')
        for part in plugin_parts:
            if '=' in part:
                k, v = part.split('=', 1)
                plugin_info[k.strip()] = v.strip()
        
    # 构建基础结构
    result = {
        "tag": name,
        "type": "shadowsocks",
        "server": hostname,
        "server_port": int(port),
        "method": method,
        "password": password
    }
    
    # 处理plugin字段
    if plugin_info.get('plugin') == 'simple-obfs':
        result['plugin'] = 'obfs-local'
        # 提取obfs相关参数
        obfs_protocol = plugin_info.get('obfs')
        obfs_host = plugin_info.get('obfs-host')
        if obfs_protocol or obfs_host:
            opts = []
            if obfs_protocol:
                opts.append(f"obfs={obfs_protocol}")
            if obfs_host:
                opts.append(f"obfs-host={obfs_host}")
            result['plugin_opts'] = ';'.join(opts)
    
    return result

def is_base64(s):
    """判断字符串是否为Base64编码"""
    try:
        decoded = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        return base64.urlsafe_b64encode(decoded).decode('utf-8').rstrip('=') == s.rstrip('=')
    except:
        return False

def parse_hysteria2_url(h2_line):
    """解析hysteria2链接行，返回结构化数据"""
    h2_line = h2_line.strip()
    if not h2_line.startswith('hysteria2://'):
        return None

    # 正则匹配hysteria2格式
    pattern = r'^hysteria2://([^@]+)@([^:]+):([^/?#]+)(?:/\?([^#]*))?#(.*)$'
    match = re.match(pattern, h2_line)
    if not match:
        return None

    auth_encoded, hostname, port_str, query_encoded, name_encoded = match.groups()
    
    # 解码name（保留原始空格）
    name = urllib.parse.unquote(name_encoded)
    
    # 处理auth（判断是否为Base64，并去除末尾换行符）
    if is_base64(auth_encoded):
        try:
            # 解码后去除末尾换行符
            auth = base64.urlsafe_b64decode(auth_encoded + '=' * (-len(auth_encoded) % 4)).decode('utf-8').rstrip('\n')
        except:
            # 解码失败时使用原始值并去除换行符
            auth = auth_encoded.rstrip('\n')
    else:
        # 非Base64时直接去除原始值的换行符
        auth = auth_encoded.rstrip('\n')
    
    # 解析查询参数（key=value&...）
    query_params = urllib.parse.parse_qs(query_encoded) if query_encoded else {}
    
    # 处理port（支持范围格式如5000-6000）
    port_info = {}
    if '-' in port_str:
        port_info['server_ports'] = [port_str.replace('-', ':')]  # 关键修改
    else:
        port_info['server_port'] = int(port_str)
    
    # 构建基础结构
    result = {
        "tag": name,
        "type": "hysteria2",
        "server": hostname,
        "password": auth,
        **port_info
    }
    
    # 处理tls字段
    tls = {"enabled": True}
    if query_params.get('insecure') == ['1']:
        tls['insecure'] = True
    if 'sni' in query_params:
        tls['server_name'] = query_params['sni'][0]
    if tls:  # 仅当有tls配置时添加
        result['tls'] = tls
    
    # 处理obfs字段
    if 'obfs' in query_params:
        obfs = {"type": query_params['obfs'][0]}
        if 'obfs-password' in query_params:
            obfs['password'] = query_params['obfs-password'][0]
        result['obfs'] = obfs
    
    return result

def filter_tags(tags, include_keywords, exclude_keywords=None, match_include=True):
    """根据关键词筛选tag列表（支持包含/不包含模式）"""
    filtered = []
    for tag in tags:
        # 判断是否包含任意include关键词
        contains_include = any(kw.lower() in tag.lower() for kw in include_keywords)
        # 根据match_include决定是否保留基础条件
        base_condition = (match_include and contains_include) or (not match_include and not contains_include)
        if not base_condition:
            continue
        
        # 处理排除关键词（如果有）
        if exclude_keywords:
            if not any(ekw.lower() in tag.lower() for ekw in exclude_keywords):
                filtered.append(tag)
        else:
            filtered.append(tag)
    return filtered

def main():
    try:
        parser = argparse.ArgumentParser(description='处理订阅源生成配置文件')
        parser.add_argument('template', help='模板文件/URL路径')
        parser.add_argument('subscriptions', nargs='+', help='订阅源文件/URL路径列表')
        args = parser.parse_args()
    
        # 获取模板内容
        template_content = get_content(args.template).decode('utf-8')
    
        # 处理所有订阅源
        all_entries = []
        for sub in args.subscriptions:
            # 获取订阅源内容（Base64加密）
            sub_encoded = get_content(sub)
            try:
                sub_decoded = base64.urlsafe_b64decode(sub_encoded + b'=' * (-len(sub_encoded) % 4)).decode('utf-8')
            except:
                print(f"警告：订阅源 {sub} 解密失败，跳过")
                continue
            
            # 逐行解析（支持ss和hysteria2）
            for line in sub_decoded.split('\n'):
                # 优先尝试ss协议解析
                entry = parse_ss_url(line)
                # 若失败则尝试hysteria2协议解析
                if not entry:
                    entry = parse_hysteria2_url(line)
                if entry:
                    all_entries.append(entry)
    
        # 生成sub_outbounds_config内容（修正JSON格式）
        sub_outbounds_config = ',\n'.join([
            json.dumps(entry, ensure_ascii=False, indent=2)  # 使用json.dumps生成标准JSON
            for entry in all_entries
        ])
        
        # 提取所有tag
        all_tags = [entry['tag'] for entry in all_entries]
    
        # 处理各占位符替换（新增 default_exclude_keywords 排除逻辑）
        replacements = {
            '{sub_outbounds_config}': sub_outbounds_config,
            # 已有 default_exclude_keywords 排除，无需修改
            '{sub_outbounds}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, default_exclude_keywords, match_include=False)),
            # 新增 exclude_keywords=default_exclude_keywords
            '{sub_outbounds_HK}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, hk_keywords, exclude_keywords=default_exclude_keywords)),
            # 新增 exclude_keywords=default_exclude_keywords（!HK 表示不包含 HK 关键词，同时排除 default）
            '{sub_outbounds_!HK}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, hk_keywords, exclude_keywords=default_exclude_keywords, match_include=False)),
            # 新增 exclude_keywords=default_exclude_keywords
            '{sub_outbounds_SG}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, sg_keywords, exclude_keywords=default_exclude_keywords)),
            # 新增 exclude_keywords=default_exclude_keywords
            '{sub_outbounds_TW}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, tw_keywords, exclude_keywords=default_exclude_keywords)),
            # 合并原有 jp_exclude_keywords 和 default_exclude_keywords
            '{sub_outbounds_JP}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, jp_keywords, exclude_keywords=jp_exclude_keywords + default_exclude_keywords)),
            # 新增 exclude_keywords=default_exclude_keywords
            '{sub_outbounds_US}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, us_keywords, exclude_keywords=default_exclude_keywords)),
            # 已有 default_exclude_keywords 排除，无需修改
            '{sub_outbounds_All}': ',\n'.join(f'  "{tag}"' for tag in filter_tags(all_tags, default_exclude_keywords, match_include=False))
        }
    
        # 执行替换
        output_content = template_content
        for placeholder, value in replacements.items():
            output_content = output_content.replace(placeholder, value)
    
        # 写入输出文件
        with open('config.json', 'w', encoding='utf-8') as f:
            f.write(output_content)
    
        print("配置文件生成完成：config.json")
    except Exception as e:
        print(f"脚本执行失败，错误信息：{str(e)}")  # 新增异常捕获

if __name__ == '__main__':
    main()
