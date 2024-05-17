package hldf.taie.analysis.pta.plugin;

import pascal.taie.analysis.pta.plugin.util.InvokeUtils;
import pascal.taie.language.classes.JMethod;

import java.util.Arrays;
import java.util.List;

/**
 * 用于记录Mybatis的污点函数
 *
 * @param method the sink method.
 * @param index  the specific index used to locate the sensitive argument
 *               at the call site of {@code method}.
 * @param field 当@param index 指向一个JavaBean时，用field记录造成拼接到sql语句的具体字段
 */
public record MybatisSink(JMethod method, int index, String field) {

    @Override
    public String toString() {
        return method + "/" + InvokeUtils.toString(index) + "/" + field;
    }
}
