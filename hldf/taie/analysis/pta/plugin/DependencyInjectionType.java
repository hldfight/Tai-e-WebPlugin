package hldf.taie.analysis.pta.plugin;

public enum DependencyInjectionType {

    AutowiredType("org.springframework.beans.factory.annotation.Autowired"),
    InjectType("javax.inject.Inject"),
    ResourceType("javax.annotation.Resource"),
    QualifierType("org.springframework.beans.factory.annotation.Qualifier");

    private final String name;

    DependencyInjectionType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
