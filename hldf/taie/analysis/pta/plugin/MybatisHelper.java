package hldf.taie.analysis.pta.plugin;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import pascal.taie.World;
import pascal.taie.language.annotation.Annotation;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;
import pascal.taie.util.collection.Sets;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * @author: hldf
 * @description:
 */
public class MybatisHelper {

    private static Pattern concatPattern = Pattern.compile("\\$\\{([\\w.]+)\\}");

    private static Pattern paramPattern = Pattern.compile("^param(\\d+)$");

    public static List<MybatisSink> isSqli(String sql, JMethod method) {
        Set<String> concatArgNames = Sets.newSet();
        List<MybatisSink> sinks = new ArrayList<>();

        Matcher matcher = concatPattern.matcher(sql);
        while(matcher.find()) {
            concatArgNames.add(matcher.group(1));
        }
        AtomicBoolean flag = new AtomicBoolean(false);
        concatArgNames.forEach(concatArgName -> {
            if (method.getParamCount() == 1) {
                Type paramType = method.getParamType(0);
                if (WebEntryParamProvider.isJavaBean(paramType)) {
                    JField field = World.get().getClassHierarchy().getClass(paramType.getName()).getDeclaredField(concatArgName);
                    if (field != null && WebEntryParamProvider.isNotPrimitiveType(field.getType())) {
                        sinks.add(new MybatisSink(method, 0, concatArgName));
                    }
                } else {
                    flag.set(true);
                }
            } else {
                for (int i = 0; i < method.getParamCount(); i++) {
                    Annotation paramAnnotation = method.getParamAnnotation(i, "org.apache.ibatis.annotations.Param");
                    if (WebEntryParamProvider.isNotPrimitiveType(method.getParamType(i))) {
                         if (paramAnnotation != null
                                && paramAnnotation.hasElement("value") && paramAnnotation.getElement("value").toString().equals("\"" + concatArgName + "\"")) {
                             sinks.add(new MybatisSink(method, i, null));
                             break;
                         } else {
                             Matcher matcher2 = paramPattern.matcher(concatArgName);
                             if (matcher2.find()) {
                                 sinks.add(new MybatisSink(method, Integer.parseInt(matcher2.group(1)) - 1, null));
                                 break;
                             }
                         }
                    }
                    flag.set(true);
                }
            }
        });
        if (flag.get()) {
            sinks.clear();
            // 由于soot生成ir时，没有保留接口中抽象方法的形参名，因此当方法未使用@Param注解传值时，这里无法通过参数名进行精确匹配，因此为了降低漏报，这里选择把所有参数都设置为sink
            for (int i = 0; i < method.getParamCount(); i++) {
                Type paramType = method.getParamType(i);
                if (WebEntryParamProvider.isNotPrimitiveType(paramType)) {
                    sinks.add(new MybatisSink(method, i, null));
                }
            }
        }
        return sinks;
    }

    private static void dealInclude(Element root, Element element, StringBuilder sql) {
        element.elements("include").forEach(includeEle -> {
            String refid = includeEle.attribute("refid").getText();
            root.elements("sql").stream().filter(sqlEle -> sqlEle.attribute("id").getText().equals(refid)).forEach(sqlEle -> {
                dealCRUD(root, sqlEle, sql);
            });
        });
    }

    private static void dealCRUD(Element root, Element element, StringBuilder sql) {
        sql.append(element.getText().strip());
        dealInclude(root, element, sql);
        for (Iterator<Element> it = element.elementIterator(); it.hasNext(); ) {
            dealCRUD(root, it.next(), sql);
        }
    }

    public static List<MybatisSink> parseXml(InputStream inputStream) {
        List<MybatisSink> sinks = new ArrayList<>();

        try {
            Document document = new SAXReader().read(inputStream);
            Element root = document.getRootElement();
            Attribute namespaceAttr = root.attribute("namespace");
            if (namespaceAttr != null) {
                String mapperNamespace = namespaceAttr.getText();
                JClass jclass = World.get().getClassHierarchy().getClass(mapperNamespace);
                if (jclass != null) {
                    for (Iterator<Element> it = root.elementIterator(); it.hasNext(); ) {
                        Element element = it.next();
                        if (element.getName().matches("(insert|update|delete|select)")) {
                            String methodName = element.attribute("id").getText();
                            JMethod jMethod = jclass.getDeclaredMethod(methodName);
                            if (jMethod != null) {
                                final StringBuilder sql = new StringBuilder();
                                dealCRUD(root, element, sql);
                                sinks.addAll(isSqli(sql.toString(), jMethod));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sinks;
    }


    public static List<MybatisSink> dealMybatisXml() {

        List<MybatisSink> sinks = new ArrayList<>();

        World.get().getOptions().getAppClassPath().forEach(appClassPath -> {
            try {
                if (appClassPath.endsWith(".jar")) {
                    JarFile jarFile = new JarFile(appClassPath);
                    Enumeration<JarEntry> entries = jarFile.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        if (entry.getName().endsWith("Mapper.xml") && !entry.isDirectory()) {
                            InputStream inputStream = jarFile.getInputStream(entry);
                            sinks.addAll(parseXml(inputStream));
                        }
                    }
                } else {
                    try (Stream<Path> paths = Files.walk(Paths.get(appClassPath))) {
                        paths.filter(path -> Files.isRegularFile(path) && path.toString().endsWith("Mapper.xml")).forEach(path -> {
                            try {
                                InputStream inputStream = new FileInputStream(path.toFile());
                                sinks.addAll(parseXml(inputStream));
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            }
                        });
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        return sinks;
    }
}
