package hldf.taie.analysis.pta.plugin;

public enum ComponentType {

    ComponentType("org.springframework.stereotype.Component"),
    ServiceType("org.springframework.stereotype.Service"),
    ControllerType("org.springframework.stereotype.Controller"),
    RestControllerType("org.springframework.web.bind.annotation.RestController");

    private final String name;


    ComponentType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
