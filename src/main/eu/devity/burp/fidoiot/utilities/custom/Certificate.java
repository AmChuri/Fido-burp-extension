package src.main.eu.devity.burp.fidoiot.utilities.custom;

public class Certificate {

    private String file;
    private String name;
    private String type;

    public Certificate() {
    }

    public Certificate(String file, String name, String type) {
        this.file = file;
        this.name = name;
        this.type = type;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return this.name;
    }
    public String getFile() {
        return this.file;
    }
    public String getType() {
        return this.type;
    }
}
