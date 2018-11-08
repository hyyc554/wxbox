Django——微信消息推送

## 前言

微信公众号的分类

- 微信消息推送
   - 公众号
     - 已认证公众号

     - 服务号

     - 已认证服务号

     - 企业号

基于：微信认证服务号 主动推送微信消息。
前提：关注服务号
环境：沙箱环境

沙箱环境地址： https://mp.weixin.qq.com/debug/cgi-bin/sandbox?t=sandbox/login





## 流程：

1. 注册开发者账号

  获得：appID、appsecret

  网页授权获取用户基本信息：47.98.134.86 或 域名 

2. 关注公众号（已认证的服务号）

   ![iHwTKA.png](https://s1.ax1x.com/2018/11/08/iHwTKA.png)

3. 生成二维码，用户扫描；
  将用户信息发送给微信，微信再将数据发送给设置redirect_uri地址(md5值)

  [![iH09rn.png](https://s1.ax1x.com/2018/11/08/iH09rn.png)](https://imgchr.com/i/iH09rn)

4. 回调地址：47.98.134.86/callback/

  ![iHfnQP.png](https://s1.ax1x.com/2018/11/08/iHfnQP.png)

  - 授权 
  - 用户md5
  - 获取wx_id 
    在数据库中更新设置：wx_id 

5. 发送消息（模板消息）
  - wx_id 

  - access_token（2小时有效期）

    ![iHfZRI.png](https://s1.ax1x.com/2018/11/08/iHfZRI.png)

## 核心代码

models.py 

``````python
import hashlib
from django.db import models

class UserInfo(models.Model):
    username = models.CharField("用户名", max_length=64, unique=True)
    password = models.CharField("密码", max_length=64)
    uid = models.CharField(verbose_name='个人唯一ID',max_length=64, unique=True)
    wx_id = models.CharField(verbose_name="微信ID", max_length=128, blank=True, null=True, db_index=True)

    def save(self, *args, **kwargs):
        # 创建用户时，为用户自动生成个人唯一ID
        if not self.pk:
            m = hashlib.md5()
            m.update(self.username.encode(encoding="utf-8"))
            self.uid = m.hexdigest()
        super(UserInfo, self).save(*args, **kwargs)
``````

settings.py

``````python
WECHAT_CONFIG = {
    'app_id': 'wx3d0d44e8d59b5b8c',
    'appsecret': 'a4ede68946e9a2e7e36480d23865a64d',
    'redirect_uri': 'http://47.106.237.76/callback/',
}
``````

views.py

``````python
import json
import functools
import requests
from django.conf import settings
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from app01 import models
# 沙箱环境地质：https://mp.weixin.qq.com/debug/cgi-bin/sandbox?t=sandbox/login
def index(request):
    obj = models.UserInfo.objects.get(id=1)
    return render(request,'index.html',{'obj':obj})


def auth(func):
    @functools.wraps(func)
    def inner(request, *args, **kwargs):
        user_info = request.session.get('user_info')
        if not user_info:
            return redirect('/login/')
        return func(request, *args, **kwargs)

    return inner


def login(request):
    """
    用户登录
    :param request: 
    :return: 
    """
    # models.UserInfo.objects.create(username='luffy',password=123)

    if request.method == "POST":
        user = request.POST.get('user')
        pwd = request.POST.get('pwd')
        obj = models.UserInfo.objects.filter(username=user, password=pwd).first()

        if obj:
            request.session['user_info'] = {'id': obj.id, 'name': obj.username, 'uid': obj.uid}
            return redirect(to='/bind/')
    else:
        return render(request, 'login.html')


@auth
def bind(request):
    """
    用户登录后，关注公众号，并绑定个人微信（用于以后消息推送）
    :param request: 
    :return: 
    """
    return render(request, 'bind.html')


@auth
def bind_qcode(request):
    """
    生成二维码
    :param request: 
    :return: 
    """
    ret = {'code': 1000}
    try:
        access_url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid={appid}&redirect_uri={redirect_uri}&response_type=code&scope=snsapi_userinfo&state={state}#wechat_redirect"
        access_url = access_url.format(
            appid=settings.WECHAT_CONFIG["app_id"], # 'wx89085e915d351cae',
            redirect_uri=settings.WECHAT_CONFIG["redirect_uri"], # 'http://47.93.4.198/test/',
            state=request.session['user_info']['uid'] # 为当前用户生成MD5值
        )
        ret['data'] = access_url
    except Exception as e:
        ret['code'] = 1001
        ret['msg'] = str(e)

    return JsonResponse(ret)


def callback(request):
    """
    用户在手机微信上扫码后，微信自动调用该方法。
    用于获取扫码用户的唯一ID，以后用于给他推送消息。
    :param request: 
    :return: 
    """
    code = request.GET.get("code")

    # 用户md5值
    state = request.GET.get("state")

    # 获取该用户openId(用户唯一，用于给用户发送消息)
    res = requests.get(
        url="https://api.weixin.qq.com/sns/oauth2/access_token",
        params={
            "appid": settings.WECHAT_CONFIG['app_id'],
            "secret": settings.WECHAT_CONFIG['appsecret'],
            "code": code,
            "grant_type": 'authorization_code',
        }
    ).json()
    # 获取的到openid表示用户授权成功
    openid = res.get("openid")
    print(openid)
    if openid:
        models.UserInfo.objects.filter(uid=state).update(wx_id=openid)
        response = "<h1>授权成功 %s </h1>" % openid
    else:
        response = "<h1>用户扫码之后，手机上的提示</h1>"
    return HttpResponse(response)


def sendmsg(request):
    def get_access_token():
        """
        获取微信全局接口的凭证(默认有效期俩个小时)
        如果不每天请求次数过多, 通过设置缓存即可
        """
        result = requests.get(
            url="https://api.weixin.qq.com/cgi-bin/token",
            params={
                "grant_type": "client_credential",
                "appid": settings.WECHAT_CONFIG['app_id'],
                "secret": settings.WECHAT_CONFIG['appsecret'],
            }
        ).json()
        if result.get("access_token"):
            access_token = result.get('access_token')
        else:
            access_token = None
        return access_token

    access_token = get_access_token()

    openid = models.UserInfo.objects.get(id=1).wx_id
    print(openid)

    def send_custom_msg():
        body = {
            "touser": openid,
            "msgtype": "text",
            "text": {
                "content": '云姐好美呀'
            }
        }
        response = requests.post(
            url="https://api.weixin.qq.com/cgi-bin/message/custom/send",
            params={
                'access_token': access_token
            },
            data=bytes(json.dumps(body, ensure_ascii=False), encoding='utf-8')
        )
        # 这里可根据回执code进行判定是否发送成功(也可以根据code根据错误信息)
        result = response.json()
        return result

    def send_template_msg():
        """
        发送模版消息
        """
        res = requests.post(
            url="https://api.weixin.qq.com/cgi-bin/message/template/send",
            params={
                'access_token': access_token
            },
            json={
                "touser": openid,
                "template_id": 'NcN_W_aEIwu-FHyJx8djU99Z70AvwwGcEufXiTzj-NM',
                "data": {
                    "first": {
                        "value": "冰姐",
                        "color": "#173177"
                    },
                    "keyword1": {
                        "value": "美女",
                        "color": "#173177"
                    },
                }
            }
        )
        result = res.json()
        return result
    # 在这里编辑要发送的函数中的内容
    result = send_template_msg()

    if result.get('errcode') == 0:
        return HttpResponse('发送成功')
    return HttpResponse('发送失败')




``````





## 功能演示

1登陆：

[![iHwYBq.png](https://s1.ax1x.com/2018/11/08/iHwYBq.png)](https://imgchr.com/i/iHwYBq)

2客户扫码关注我们的公众号

[![iHwTKA.png](https://s1.ax1x.com/2018/11/08/iHwTKA.png)](https://imgchr.com/i/iHwTKA)



为了获得用户的微信ID，我们需要客户再次扫码，向微信授权把ID给我们

[![iH09rn.png](https://s1.ax1x.com/2018/11/08/iH09rn.png)](https://imgchr.com/i/iH09rn)



## 源码：

https://github.com/hyyc554/wxbox