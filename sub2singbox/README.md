# sub2singbox

将订阅转换为 [sing-box](https://github.com/SagerNet/sing-box) 配置文件

目前支持:

- SS 订阅转换

## 用法

```
python ./main.py 订阅模板 订阅源(可多个)
```

模板和订阅源可以是本地文件，也可以是 URL 链接

订阅源需要是 Base64 文件

## 解释

用于 `outbounds` 中，添加所有出口节点配置信息

`{sub_outbounds_ALL}` 所有节点信息

---

以下用于 `selector` 和 `urltest` 类型的 `"outbounds":[]` ，会被替代成所有的 `tag` 对应名称

`{sub_outbounds}` 所有节点

`{sub_outbounds_HK}` 所有香港节点

`{sub_outbounds_!HK}` 所有**非**香港节点

`{sub_outbounds_SG}` 所有新加坡节点

