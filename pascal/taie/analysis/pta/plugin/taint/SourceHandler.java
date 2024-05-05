/*
 * Tai-e: A Static Analysis Framework for Java
 *
 * Copyright (C) 2022 Tian Tan <tiantan@nju.edu.cn>
 * Copyright (C) 2022 Yue Li <yueli@nju.edu.cn>
 *
 * This file is part of Tai-e.
 *
 * Tai-e is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Tai-e is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Tai-e. If not, see <https://www.gnu.org/licenses/>.
 */

package pascal.taie.analysis.pta.plugin.taint;

import hldf.taie.analysis.pta.plugin.WebEntryParamProvider;
import hldf.taie.analysis.pta.plugin.WebPlugin;
import pascal.taie.analysis.graph.callgraph.CallKind;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.pta.core.cs.context.Context;
import pascal.taie.analysis.pta.core.cs.element.CSCallSite;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.analysis.pta.core.cs.element.CSObj;
import pascal.taie.analysis.pta.core.heap.Descriptor;
import pascal.taie.analysis.pta.core.heap.MockObj;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.plugin.util.InvokeUtils;
import pascal.taie.ir.IR;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.LoadField;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.ArrayType;
import pascal.taie.language.type.ClassType;
import pascal.taie.language.type.PrimitiveType;
import pascal.taie.language.type.Type;
import pascal.taie.util.collection.Maps;
import pascal.taie.util.collection.MultiMap;
import pascal.taie.util.collection.Pair;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Handles sources in taint analysis.
 */
class SourceHandler extends OnFlyHandler {

    /**
     * Map from a source method to its result sources.
     */
    private final MultiMap<JMethod, CallSource> callSources = Maps.newMultiMap();

    /**
     * Map from a method to {@link Invoke} statements in the method
     * which matches any call source.
     * This map matters only when call-site mode is enabled.
     */
    private final MultiMap<JMethod, Invoke> callSiteSources = Maps.newMultiMap();

    /**
     * Map from a source method to its parameter sources.
     */
    private final MultiMap<JMethod, ParamSource> paramSources = Maps.newMultiMap();

    /**
     * Whether this handler needs to handle field sources.
     */
    private final boolean handleFieldSources;

    /**
     * Map from a source field taint objects generated from it.
     */
    private final Map<JField, Type> fieldSources = Maps.newMap();

    /**
     * Maps from a method to {@link LoadField} statements in the method
     * which loads a source field.
     */
    private final MultiMap<JMethod, LoadField> loadedFieldSources = Maps.newMultiMap();

    SourceHandler(HandlerContext context) {
        super(context);
        context.config().sources().forEach(src -> {
            if (src instanceof CallSource callSrc) {
                callSources.put(callSrc.method(), callSrc);
            } else if (src instanceof ParamSource paramSrc) {
                paramSources.put(paramSrc.method(), paramSrc);
            } else if (src instanceof FieldSource fieldSrc) {
                fieldSources.put(fieldSrc.field(), fieldSrc.type());
            }
        });
        handleFieldSources = !fieldSources.isEmpty();
    }

    /**
     * Generates taint objects from call sources.
     */
    private void processCallSource(Context context, Invoke callSite, CallSource source) {
        int index = source.index();
        if (InvokeUtils.RESULT == index && callSite.getLValue() == null) {
            return;
        }
        Var var = InvokeUtils.getVar(callSite, index);
        SourcePoint sourcePoint = new CallSourcePoint(callSite, index);
        Obj taint = manager.makeTaint(sourcePoint, source.type());
        solver.addVarPointsTo(context, var, taint);
    }

    /**
     * Handles call sources.
     */
    @Override
    public void onNewCallEdge(Edge<CSCallSite, CSMethod> edge) {
        if (edge.getKind() == CallKind.OTHER) {
            return;
        }
        Set<CallSource> sources = callSources.get(edge.getCallee().getMethod());
        if (!sources.isEmpty()) {
            Context context = edge.getCallSite().getContext();
            Invoke callSite = edge.getCallSite().getCallSite();
            sources.forEach(source -> processCallSource(context, callSite, source));
        }

    }

    @Override
    public void onNewStmt(Stmt stmt, JMethod container) {
        if (handleFieldSources && stmt instanceof LoadField loadField) {
            // Handle field sources.
            // If a {@link LoadField} loads any source fields,
            // then records the {@link LoadField} statements.
            JField field = loadField.getFieldRef().resolveNullable();
            if (fieldSources.containsKey(field)) {
                loadedFieldSources.put(container, loadField);
            }
        }
        if (callSiteMode &&
                stmt instanceof Invoke invoke &&
                !invoke.isDynamic()) {
            // Handles call sources for the case when call-site mode is enabled.
            // If method references of any {@link Invoke}s are resolved to
            // call source method, then records the {@link Invoke} statements.
            JMethod callee = invoke.getMethodRef().resolveNullable();
            if (callSources.containsKey(callee)) {
                callSiteSources.put(container, invoke);
            }
        }
    }

    @Override
    public void onNewCSMethod(CSMethod csMethod) {
        handleParamSource(csMethod);
        if (handleFieldSources) {
            handleFieldSource(csMethod);
        }
        if (callSiteMode) {
            handleCallSource(csMethod);
        }
    }

    private void handleParamSource(CSMethod csMethod) {
        JMethod method = csMethod.getMethod();
        if (paramSources.containsKey(method)) {
            Context context = csMethod.getContext();
            IR ir = method.getIR();
            paramSources.get(method).forEach(source -> {
                int index = source.index();
                Var param = ir.getParam(index);
                SourcePoint sourcePoint = new ParamSourcePoint(method, index);
                Type type = source.type();
                Obj taint = manager.makeTaint(sourcePoint, type);
                solver.addVarPointsTo(context, param, taint);
            });
        }
        // 为SpringMVC的入口函数的形参列表创建污点对象
        else if(WebPlugin.isSpringMVController(csMethod.getMethod().getDeclaringClass())
                && WebPlugin.isSpringMVCRequest(csMethod.getMethod())) {
            Context context = csMethod.getContext();
            IR ir = method.getIR();
            for (int i = 0; i < method.getParamCount(); ++i) {
                Type paramType = method.getParamType(i);
                // 仅给可实例化且非基础类型的对象创建污点对象
                if (WebEntryParamProvider.isInstantiable(paramType) && !(paramType instanceof PrimitiveType) && !WebEntryParamProvider.isBoxedType(paramType)) {
                    SourcePoint sourcePoint = new ParamSourcePoint(method, i);
                    Obj taint = manager.makeTaint(sourcePoint, paramType);
                    solver.addVarPointsTo(context, ir.getParam(i), taint);
                }
            }
        }
    }

    /**
     * If given method contains pre-recorded {@link LoadField} statements,
     * adds corresponding taint object to LHS of the {@link LoadField}.
     */
    private void handleFieldSource(CSMethod csMethod) {
        JMethod method = csMethod.getMethod();
        Set<LoadField> loads = loadedFieldSources.get(method);
        if (!loads.isEmpty()) {
            Context context = csMethod.getContext();
            loads.forEach(load -> {
                Var lhs = load.getLValue();
                SourcePoint sourcePoint = new FieldSourcePoint(method, load);
                JField field = load.getFieldRef().resolve();
                Type type = fieldSources.get(field);
                Obj taint = manager.makeTaint(sourcePoint, type);
                solver.addVarPointsTo(context, lhs, taint);
            });
        }
    }

    /**
     * If given method contains pre-recorded {@link Invoke} statements,
     * call {@link #processCallSource} to generate taint objects.
     */
    private void handleCallSource(CSMethod csMethod) {
        JMethod method = csMethod.getMethod();
        Set<Invoke> callSites = callSiteSources.get(method);
        if (!callSites.isEmpty()) {
            Context context = csMethod.getContext();
            callSites.forEach(callSite -> {
                JMethod callee = callSite.getMethodRef().resolve();
                callSources.get(callee).forEach(source ->
                        processCallSource(context, callSite, source));
            });
        }
    }


    /**
     * 当污点分析配置文件中，配置的污点源为抽象函数时，在此进行处理
     *
     */
    @Override
    public void onUnresolvedCall(CSObj recv, Context context, Invoke invoke) {
        Set<CallSource> sources = callSources.get(invoke.getMethodRef().resolve());
        if (!sources.isEmpty()) {
            sources.forEach(source -> processCallSource(context, invoke, source));
        }
    }

    /**
     *  处理SpringMVC入口函数中的JavaBean对象，将其属性值设置为污点源
     *
     */
    @Override
    public void onCallWebEntryParamObjGetter(Context context, Invoke invoke, JMethod callee) {
        Var var = InvokeUtils.getVar(invoke, InvokeUtils.RESULT);
        SourcePoint sourcePoint = new CallSourcePoint(invoke, InvokeUtils.RESULT);
        Obj taint = manager.makeTaint(sourcePoint, callee.getReturnType());
        solver.addVarPointsTo(context, var, taint);
    }
}
