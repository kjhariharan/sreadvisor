from pathlib import Path

from sreadvisor.code.fingerprint import fingerprint_repo

POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.3.1</version>
  </parent>
  <properties><java.version>21</java.version><resilience.version>2.2.0</resilience.version></properties>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>io.github.resilience4j</groupId><artifactId>resilience4j-spring-boot3</artifactId><version>${resilience.version}</version></dependency>
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  </dependencies>
</project>"""


def write(tmp: Path, name: str, text: str) -> None:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_maven_spring_boot(tmp_path):
    write(tmp_path, "pom.xml", POM)
    fp = fingerprint_repo(tmp_path)
    assert fp.languages == ["Java"]
    assert fp.runtime_versions["java"] == "21"
    spring = next(f for f in fp.frameworks if f.name == "Spring Boot")
    assert spring.version == "3.3.1" and spring.evidence[0].line == 3
    resilience = next(d for d in fp.dependencies if d.name == "resilience4j-spring-boot3")
    assert resilience.version == "2.2.0" and "resilience" in resilience.categories
    pg = next(d for d in fp.dependencies if d.name == "postgresql")
    assert pg.categories == ["datastore"] and pg.evidence.line == 12
    test_dep = next(d for d in fp.dependencies if d.name == "spring-boot-starter-test")
    assert test_dep.categories == ["test"]


def test_quarkus_gradle(tmp_path):
    write(tmp_path, "build.gradle", """
plugins { id 'java'
  id 'io.quarkus' version '3.8.0' }
sourceCompatibility = '17'
dependencies {
  implementation 'io.quarkus:quarkus-resteasy-reactive'
  implementation("io.quarkus:quarkus-smallrye-fault-tolerance")
  testImplementation 'io.quarkus:quarkus-junit5'
}""")
    fp = fingerprint_repo(tmp_path)
    assert any(f.name == "Quarkus" and f.version == "3.8.0" for f in fp.frameworks)
    assert fp.runtime_versions["java"] == "17"
    ft = next(d for d in fp.dependencies if d.name == "quarkus-smallrye-fault-tolerance")
    assert "resilience" in ft.categories


def test_npm_and_typescript(tmp_path):
    write(tmp_path, "package.json", '{"name":"x","engines":{"node":">=20"},"dependencies":{"express":"^4.19.0","pg":"^8"},'
                                    '"devDependencies":{"typescript":"^5","jest":"^29"}}')
    fp = fingerprint_repo(tmp_path)
    assert fp.languages == ["JavaScript", "TypeScript"]
    assert fp.runtime_versions["node"] == ">=20"
    assert [f.name for f in fp.frameworks] == ["Express"]
    assert next(d for d in fp.dependencies if d.name == "jest").categories == ["test"]


def test_python_pyproject_and_requirements(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nrequires-python = ">=3.11"\ndependencies = ["fastapi>=0.110", "tenacity==8.2.3", "sqlalchemy"]\n')
    write(tmp_path, "requirements.txt", "flask==3.0.0  # web\n-r other.txt\n")
    fp = fingerprint_repo(tmp_path)
    names = {f.name for f in fp.frameworks}
    assert {"FastAPI", "Flask"} <= names
    assert fp.runtime_versions["python"] == ">=3.11"
    assert "resilience" in next(d for d in fp.dependencies if d.name == "tenacity").categories


def test_dotnet_csproj(tmp_path):
    write(tmp_path, "src/Api/Api.csproj", """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Polly" Version="8.3.0" />
    <PackageReference Include="Npgsql.EntityFrameworkCore.PostgreSQL" Version="8.0.2" />
  </ItemGroup></Project>""")
    fp = fingerprint_repo(tmp_path)
    assert fp.languages == ["C#"] and fp.runtime_versions["dotnet"] == "net8.0"
    assert any(f.name == "ASP.NET Core" for f in fp.frameworks)
    assert "resilience" in next(d for d in fp.dependencies if d.name == "Polly").categories


def test_malformed_manifest_is_reported_not_fatal(tmp_path):
    write(tmp_path, "pom.xml", "<project><dependencies></project>")
    write(tmp_path, "package.json", "{not json")
    fp = fingerprint_repo(tmp_path)
    assert len(fp.parse_errors) == 2
