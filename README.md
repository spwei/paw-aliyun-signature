# Aliyun Signature

Dynamic value that returns the common parameters with signature of Aliyun API.

For [Paw.app](https://luckymarmot.com/paw)

## Install
1. Clone或者下载Zip
2. 将文件夹复制到Paw的扩展目录下：~/Library/Containers/com.luckymarmot.Paw/Data/Library/Application Support/com.luckymarmot.Paw/Extensions
3. 将文件夹名字重命名为com.weibo.api.AliyunSignature

## Screenshots
<div>
  <p><img src="https://github.com/spwei/paw-aliyun-signature/blob/master/screenshots/api.png" /></p>
  <p><img src="https://github.com/spwei/paw-aliyun-signature/blob/master/screenshots/config.png" /></p>
</div>

## Usage
### GET
公用参数只需添加Action 和 Signature，其中Signature的值设置为此扩展提供的动态值
### POST
方式一：所有公用参数都要添加在外面

方式二：和GET一样添加参数，仅仅将超大参数放入UrlEncodeBody中

## Contributor
@[spwei](https://github.com/spwei)
