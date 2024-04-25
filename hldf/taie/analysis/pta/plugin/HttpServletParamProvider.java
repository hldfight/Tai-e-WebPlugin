package hldf.taie.analysis.pta.plugin;

import pascal.taie.analysis.pta.core.heap.Descriptor;
import pascal.taie.analysis.pta.core.heap.HeapModel;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.core.solver.ParamProvider;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.*;
import pascal.taie.util.collection.Maps;
import pascal.taie.util.collection.MultiMap;
import pascal.taie.util.collection.Pair;
import pascal.taie.util.collection.TwoKeyMultiMap;

import javax.annotation.Nullable;
import java.util.*;

/**
 * 该类在pascal.taie.analysis.pta.core.solver.DeclaredParamProvider基础上，
 * 添加了为HttpServletRequest类型的变量创建指针分析对象。
 */
public class HttpServletParamProvider implements ParamProvider {

    private static final String HttpServletRequestName = "javax.servlet.http.HttpServletRequest";
    private static final String RequestFacadeName = "org.apache.catalina.connector.RequestFacade";


    /**
     * Special index representing "this" variable.
     */
    private static final int THIS_INDEX = -1;

    /**
     * Represents combination of a method and a parameter index.
     *
     * @param method the entry method
     * @param index  the index of the parameter
     */
    private record MethodParam(JMethod method, int index) {

        @Override
        public String toString() {
            return "MethodParam{" + method + '/' +
                    (index == THIS_INDEX ? "this" : index) + '}';
        }
    }

    private Solver solver;

    @Nullable
    private Obj thisObj;

    private Obj[] paramObjs;

    private TwoKeyMultiMap<Obj, JField, Obj> fieldObjs;

    private MultiMap<Obj, Obj> arrayObjs;

    /**
     * @param method    the entry method.
     * @param heapModel the model for generating mock objects.
     */
    public HttpServletParamProvider(Solver solver, JMethod method, HeapModel heapModel) {
        this(solver, method, heapModel, 0);
    }

    /**
     * @param method    the entry method.
     * @param heapModel the model for generating mock objects.
     * @param k         level of field/array accesses. If this is not 0,
     *                  the provider generates objects recursively along
     *                  k field/array accesses.
     */
    public HttpServletParamProvider(Solver solver, JMethod method, HeapModel heapModel, int k) {
        this.solver = solver;
        generateObjs(method, heapModel, k);
    }

    private void generateObjs(JMethod method, HeapModel heapModel, int k) {
        Deque<Pair<Obj, Integer>> queue = new ArrayDeque<>();
        // generate this (receiver) object
        if (!method.isStatic() && !method.getDeclaringClass().isAbstract()) {
            thisObj = heapModel.getMockObj(Descriptor.ENTRY_DESC,
                    new HttpServletParamProvider.MethodParam(method, THIS_INDEX),
                    method.getDeclaringClass().getType(), method);
            queue.add(new Pair<>(thisObj, 0));
        }
        // generate parameter objects
        paramObjs = new Obj[method.getParamCount()];
        Type requestFacadeType = new TypeSystemImpl(this.solver.getHierarchy()).getType(RequestFacadeName);
        for (int i = 0; i < method.getParamCount(); ++i) {
            Type paramType = method.getParamType(i);
            // 为HttpServletRequest类型的变量创建抽象对象，该对象为HttpServletRequest接口的具体实现类RequestFacade
            if (isHttpServletRequest(paramType) && requestFacadeType instanceof ClassType cType && cType.getJClass() != null) {
                paramObjs[i] = heapModel.getMockObj(() -> "ServletBuiltInObj",
                        new HttpServletParamProvider.MethodParam(method, i), requestFacadeType, method);
                queue.add(new Pair<>(paramObjs[i], 0));
            } else if (isInstantiable(paramType)) {
                paramObjs[i] = heapModel.getMockObj(Descriptor.ENTRY_DESC,
                        new HttpServletParamProvider.MethodParam(method, i), paramType, method);
                queue.add(new Pair<>(paramObjs[i], 0));
            }
        }
        // generate k-level field and array objects by a level-order traversal
        fieldObjs = Maps.newTwoKeyMultiMap();
        arrayObjs = Maps.newMultiMap();
        while (!queue.isEmpty()) {
            Pair<Obj, Integer> pair = queue.pop();
            Obj base = pair.first();
            int level = pair.second();
            if (level < k) {
                Type type = base.getType();
                if (type instanceof ClassType cType) {
                    for (JField field : cType.getJClass().getDeclaredFields()) {
                        Type fieldType = field.getType();
                        if (isInstantiable(fieldType)) {
                            Obj obj = heapModel.getMockObj(Descriptor.ENTRY_DESC,
                                    base.getAllocation() + "." + field.getName(),
                                    fieldType, method);
                            fieldObjs.put(base, field, obj);
                            queue.add(new Pair<>(obj, level + 1));
                        }
                    }
                } else if (type instanceof ArrayType aType) {
                    Type elemType = aType.elementType();
                    if (isInstantiable(elemType)) {
                        Obj elem = heapModel.getMockObj(Descriptor.ENTRY_DESC,
                                base.getAllocation() + "[*]",
                                elemType, method);
                        arrayObjs.put(base, elem);
                        queue.add(new Pair<>(elem, level + 1));
                    }
                }
            }
        }
    }

    private static boolean isInstantiable(Type type) {
        return (type instanceof ClassType cType && !cType.getJClass().isAbstract())
                || type instanceof ArrayType;
    }

    private static boolean isHttpServletRequest(Type type) {
        return type instanceof ClassType cType && cType.getName().equals(HttpServletRequestName);
    }

    @Override
    public Set<Obj> getThisObjs() {
        return thisObj != null ? Set.of(thisObj) : Set.of();
    }

    @Override
    public Set<Obj> getParamObjs(int i) {
        return paramObjs[i] != null ? Set.of(paramObjs[i]) : Set.of();
    }

    @Override
    public TwoKeyMultiMap<Obj, JField, Obj> getFieldObjs() {
        return Maps.unmodifiableTwoKeyMultiMap(fieldObjs);
    }

    @Override
    public MultiMap<Obj, Obj> getArrayObjs() {
        return Maps.unmodifiableMultiMap(arrayObjs);
    }
}
