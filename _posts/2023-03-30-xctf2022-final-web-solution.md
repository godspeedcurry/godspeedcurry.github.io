---
layout: post
title: XCTF2022 final web solution
date: 2023-03-30 20:28 +0800
categories: [ctf, web]
tag: [xctf]
---

# Sign in
## 赛题描述
前端题。本题需要分析`index.hash.js`的逻辑,分析过程还是比较繁琐痛苦的,分析前有几个问题需要思考：
* burp抓到的密码是加密的，他的处理逻辑是什么？
* 管理员的密码从何而来？
* 能未授权访问吗？

## 分析思路
首先一眼看到一些字符串，这些字符串有助于我们判断函数的功能。从函数最后往上看：
```javascript
function hD() {
    var e = P("h1", {
        children: "404 Not Found"
    });
    return P($n, {
        children: P(kL, {
            store: pD, //存了一个变量
            children: ce(g2, {
                children: [P(Ln, {
                    index: !0,
                    element: P(vD, {})
                }), P(Ln, {
                    path: "/login",
                    element: P(FL, {
                        t: P2()
                    })
                }), P(Ln, {
                    path: "/logout",
                    element: P(LL, {})
                }), ce(Ln, {
                    path: "/user",
                    element: P(rD, {}),
                    children: [P(Ln, {
                        index: !0,
                        element: P(Ts, {
                            to: "/user/home",
                            replace: !0
                        })
                    }), P(Ln, {
                        path: "/user/home",
                        element: P(jL, {})
                    }), P(Ln, {
                        path: "*",
                        element: e
                    })]
                }), P(Ln, {
                    path: "*",
                    element: e
                })]
            })
        })
    })
}
```
以`login`为例，这里用到了以下几个变量
```javascript
P(Ln, {
    path: "/login",
    element: P(FL, {
        t: P2() 
    })
    }
)
/*==========================================================================================*/
FL = RL(AL, IL)($L)

/*==========================================================================================*/
Wx.g.login(t.au.n, $5(t.au.p + t.t).toString(), t.t)
```
阅读函数逻辑后，可以知道，
* P2 产生 token
* FL 用到了$L
* t.t是token，t.au.n是username，t.au.p是密码
* 搜索$5的魔数可知是md5

> 也就是可以得出如下结论，burp抓到的是`md5(password + token)`

假设在渗透时，分析到这里就足够了，但在CTF里面还完全不够！

接下来分析`pD`变量，这个在一开始就store了


```javascript
dD = aD({
    au: fD
}),
pD = tb(dD),

/*==========================================================================================*/

const fD = (e = {
    n: sD(),
    p: cD()
}, t)

/*==========================================================================================*/

const lD = [
        [114, 111],
        [111, 116]
    ],
    sD = () => nb(lD),
    uD = [
        [54, 52],
        [100, 102],
        [57, 51],
        [48, 97],
        [52, 51],
        [52, 50],
        [51, 53],
        [101, 97],
        [97, 51],
        [52, 97],
        [57, 56],
        [55, 99],
        [55, 101],
        [55, 49],
        [53, 98],
        [101, 102]
    ],
cD = () => nb(uD),

nb = e => String.fromCharCode(...e.flat()),
```
看到这里对ascii敏感的话就很清晰了，这些是一些字符串！
写个脚本转一下，答案就是
`root`和`64df930a434235eaa34a987c7e715bef`
登录一下完事，然后根据tips以HTTP3访问`index.hash.js`，发现新的路由，访问一下就得到flag了。

## 动态调试
我们也可以用动态调试的办法去做：

首先Redux中的`Store`有以下职责
* 维持应用的状态
* 提供`getState()`方法获取应用状态
* 提供`dispatch(action)`方法更新应用状态
* 通过`subscribe(listener)`注册监听器
* 通过`subscribe(listener)`返回的函数注销监听器

一个网上的例子如下
```javascript
import { createStore } from 'redux'
import todoApp from './reducers'
let store = createStore(todoApp)
import {
  addTodo,
  toggleTodo,
  setVisibilityFilter,
  VisibilityFilters
} from './actions'

// 打印初始状态
console.log(store.getState())

// 每次 state 更新时，打印日志
// 注意 subscribe() 返回一个函数用来注销监听器
const unsubscribe = store.subscribe(() =>
  console.log(store.getState())
)

// 发起一系列 action
store.dispatch(addTodo('Learn about actions'))
store.dispatch(addTodo('Learn about reducers'))
store.dispatch(addTodo('Learn about store'))
store.dispatch(toggleTodo(0))
store.dispatch(toggleTodo(1))
store.dispatch(setVisibilityFilter(VisibilityFilters.SHOW_COMPLETED))

// 停止监听 state 更新
unsubscribe();
```

给几个`pD`打上断点，运行一下就可断住。当出现下图时，
![](/assets/img/2023-03-30-23-03-25.png)
此时在console可以使用`pD.getState()`获取当前的应用状态，里面存着root的账号和密码

## 能否未授权
`/user/home`显然是一个值得注意的点，我们跟踪一下，发现在远程会展示`Tips: Loading...`的内容,看起来没法未授权。估计题目在后端判断了一下，真正的tips需要获取用户名和密码才行，相关代码如下：
```javascript
function $_() {
    return Ua.get("/info")
}

/*==========================================================================================*/

const I_ = Object.freeze(Object.defineProperty({
        __proto__: null,
        login: M_,
        info: $_
        ...
}))

/*==========================================================================================*/
jL = () => {
    const t = ja(),
        [e, n] = m.exports.useState("Loading...");
    return m.exports.useEffect(() => {
        Wx.g.info().then(e => {
            n(e.data)
        }).catch(e => {
            Hv.error({
                message: "Error",
                description: e.message,
                duration: 10,
                placement: "topLeft"
            }), 401 == e.code && t("/")
        })
    }, []), P("div", {
        className: zL.container,
        children: ce("h1", {
            children: ["Tips: ", e, "?"]
        })
    })
}
```
