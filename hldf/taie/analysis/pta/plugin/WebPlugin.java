package hldf.taie.analysis.pta.plugin;

import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import pascal.taie.Main;
import pascal.taie.World;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.ClassType;
import pascal.taie.util.collection.Sets;

import java.beans.JavaBean;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class WebPlugin implements Plugin {

    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    @Override
    public void onStart() {
        // 将web类的方法添加到入口函数
        World.get().getClassHierarchy().applicationClasses()
                .filter(jClass -> !jClass.isAbstract() && !jClass.isInterface())
                .forEach((jClass -> {
                    if (WebPlugin.isSpringMVController(jClass)) {
                        jClass.getDeclaredMethods().stream().filter(WebPlugin::isSpringMVCRequest)
                                .forEach(jMethod -> {
                                    // 将@Controller中的方法添加为入口点，并为所有形参创建抽象对象
                                    solver.addEntryPoint(new EntryPoint(jMethod,
                                            new WebEntryParamProvider(jMethod, solver.getHeapModel(), 3)));
                                });
                    }
                    else if (isServlet(jClass)) {
                        jClass.getDeclaredMethods().stream().filter(this::isServletRequest)
                                .forEach(jMethod -> {
                                    // 将Servlet中的doGet等方法添加为入口点，并为所有形参创建抽象对象
                                    solver.addEntryPoint(new EntryPoint(jMethod,
                                            new WebEntryParamProvider(jMethod, solver.getHeapModel(), 3)));
                                });
                    } else if (isJSP(jClass)) {
                        jClass.getDeclaredMethods().stream().filter(this::isJSPRequest)
                                .forEach(jMethod -> {
                                    // 将JSP类中的_jspService方法添加为入口点，并为所有形参创建抽象对象
                                    solver.addEntryPoint(new EntryPoint(jMethod,
                                            new WebEntryParamProvider(jMethod, solver.getHeapModel(), 3)));
                                });
                    } else if (isStruts2Action(jClass)) {
                        jClass.getDeclaredMethods().stream().filter(this::isServletExecute)
                                .forEach(jMethod -> {
                                    // 将Struts2类中的execute方法添加为入口点
                                    solver.addEntryPoint(new EntryPoint(jMethod,
                                            new WebEntryParamProvider(jMethod, solver.getHeapModel(), 3)));
                                });
                    }
                }));
    }

    private boolean isServletExecute(JMethod jMethod) {
        return jMethod.getName().equals("execute");
    }

    private boolean isStruts2Action(JClass jClass) {
        JClass superClazz = jClass.getSuperClass();
        if (superClazz != null) {
            return superClazz.getName().equals("com.opensymphony.xwork2.ActionContext");
        }
        return false;
    }

    private boolean isJSPRequest(JMethod jMethod) {
        return jMethod.getName().equals("_jspService");
    }

    private boolean isJSP(JClass jClass) {
        JClass superClazz = jClass.getSuperClass();
        if (superClazz != null) {
            return superClazz.getName().equals("org.apache.jasper.runtime.HttpJspBase") && jClass.getSimpleName().endsWith("_jsp");
        }
        return false;
    }

    private boolean isServletRequest(JMethod jMethod) {
        return jMethod.getName().matches("do(Get|Head|Post|Put|Delete|Options|Trace|)") ||
                jMethod.getName().equals("service");
    }

    private boolean isServlet(JClass jClass) {
        JClass superClazz = jClass.getSuperClass();
        if (superClazz != null) {
            return superClazz.getName().equals("javax.servlet.http.HttpServlet");
        }
        return false;
    }

    public static boolean isSpringMVCRequest(JMethod jMethod) {
        return jMethod.getAnnotations().stream().anyMatch(annotation -> annotation.getType().matches("org.springframework.web.bind.annotation.\\w+Mapping"));
    }

    public static boolean isSpringMVController(JClass jClass) {
        return jClass.getAnnotations().stream().anyMatch(annotation -> annotation.getType().equals(ComponentType.ControllerType.getName())
                || annotation.getType().equals(ComponentType.RestControllerType.getName()));
    }



}
