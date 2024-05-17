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

import hldf.taie.analysis.pta.plugin.MybatisHelper;
import hldf.taie.analysis.pta.plugin.MybatisSink;
import hldf.taie.analysis.pta.plugin.WebEntryParamProvider;
import pascal.taie.World;
import pascal.taie.analysis.graph.callgraph.CallKind;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.pta.PointerAnalysisResult;
import pascal.taie.analysis.pta.core.cs.context.Context;
import pascal.taie.analysis.pta.core.cs.element.ArrayIndex;
import pascal.taie.analysis.pta.core.cs.element.CSObj;
import pascal.taie.analysis.pta.core.heap.MockObj;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.plugin.util.InvokeUtils;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.annotation.Annotation;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;
import pascal.taie.util.collection.MultiMap;
import pascal.taie.util.collection.MultiMapCollector;
import pascal.taie.util.collection.Sets;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles sinks in taint analysis.
 */
class SinkHandler extends OnFlyHandler {

    private final List<Sink> sinks;

    private final List<MybatisSink> mybatisSinks;

    SinkHandler(HandlerContext context) {
        super(context);
        sinks = context.config().sinks();
        mybatisSinks = context.config().mybatisSinks();
    }

    Set<TaintFlow> collectTaintFlows() {
        PointerAnalysisResult result = solver.getResult();
        Set<TaintFlow> taintFlows = Sets.newOrderedSet();
        sinks.forEach(sink -> {
            int i = sink.index();
            result.getCallGraph()
                    .edgesInTo(sink.method())
                    // TODO: handle other call edges
                    .filter(e -> e.getKind() != CallKind.OTHER)
                    .map(Edge::getCallSite)
                    .forEach(sinkCall -> {
                        Var arg = InvokeUtils.getVar(sinkCall, i);
                        SinkPoint sinkPoint = new SinkPoint(sinkCall, i);
                        result.getPointsToSet(arg)
                                .stream()
                                .filter(manager::isTaint)
                                .map(manager::getSourcePoint)
                                .map(sourcePoint -> new TaintFlow(sourcePoint, sinkPoint))
                                .forEach(taintFlows::add);
                    });
        });
        mybatisSinks.forEach(sink -> {
            int i = sink.index();
            String f = sink.field();
            result.getCallGraph()
                    .edgesInTo(sink.method())
                    // TODO: handle other call edges
                    .filter(e -> e.getKind() != CallKind.OTHER)
                    .map(Edge::getCallSite)
                    .forEach(sinkCall -> {
                        Var arg = InvokeUtils.getVar(sinkCall, i);
                        SinkPoint sinkPoint = new SinkPoint(sinkCall, i);
                        result.getPointsToSet(arg)
                                .stream()
                                .map(obj -> {
                                    Type objType = obj.getType();
                                    if (f != null) {
                                        JField jField = World.get().getClassHierarchy().getClass(objType.getName()).getDeclaredField(f);
                                        if (jField != null) {
                                            for (Obj fieldObj: result.getPointsToSet(obj, jField)) {
                                                if (manager.isTaint(fieldObj)) {
                                                    return fieldObj;
                                                }
                                            }
                                        }
                                    }
                                    return obj;
                                })
                                .filter(manager::isTaint)
                                .map(manager::getSourcePoint)
                                .map(sourcePoint -> new TaintFlow(sourcePoint, sinkPoint))
                                .forEach(taintFlows::add);
                    });
        });
        if (callSiteMode) {
            MultiMap<JMethod, Sink> sinkMap = sinks.stream()
                    .collect(MultiMapCollector.get(Sink::method, s -> s));
            // scan all reachable call sites to search sink calls
            result.getCallGraph()
                    .reachableMethods()
                    .filter(m -> !m.isAbstract())
                    .flatMap(m -> m.getIR().invokes(false))
                    .forEach(callSite -> {
                        JMethod callee = callSite.getMethodRef().resolveNullable();
                        if (callee == null) {
                            return;
                        }
                        for (Sink sink : sinkMap.get(callee)) {
                            int i = sink.index();
                            Var arg = InvokeUtils.getVar(callSite, i);
                            SinkPoint sinkPoint = new SinkPoint(callSite, i);
                            result.getPointsToSet(arg)
                                    .stream()
                                    .filter(manager::isTaint)
                                    .map(manager::getSourcePoint)
                                    .map(sourcePoint -> new TaintFlow(sourcePoint, sinkPoint))
                                    .forEach(taintFlows::add);
                        }
                    });
        }
        return taintFlows;
    }

    /**
     * 将Mybatis中存在sql注入的函数加入sink
     *
     */
    @Override
    public void onCallMybatisMethod(CSObj recv, Invoke invoke) {
        if (recv.getObject() instanceof MockObj mockObj && mockObj.getDescriptor().string().equals("DependencyInjectionMapperObj")) {
            JMethod method = invoke.getMethodRef().resolve();
            method.getAnnotations().stream()
                    .filter(annotation -> annotation.getType().matches("org\\.apache\\.ibatis\\.annotations\\.(Select|Delete|Insert|Update)") && annotation.hasElement("value"))
                    .forEach(annotation -> {
                        String sql = annotation.getElement("value").toString();
                        mybatisSinks.addAll(MybatisHelper.isSqli(sql, method));
                    });
        }
    }
}
