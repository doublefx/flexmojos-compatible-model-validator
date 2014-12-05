FlexMojos Compatible Model Validator.
==========

FlexMojos provides 6 scopes used as linkages for your dependencies:

<dl>
<dt><strong>merged (Merged Into Code)</strong></dt>
<dd>This bundles in all classes from the library that are used in the project. It corresponds to the library-path option of mxmlc and compc.</dd>
<dt><strong>external</strong></dt>
<dd>This compiles the SWF or SWC against the classes from the library for linkage but does not add them into the resulting file. It corresponds to the external-library-path compiler option.</dd>
<dt><strong>internal</strong></dt>
<dd>This compiles all the libraries used into the final SWF, It corresponds to the mxmlc option -include-libraries [library] [...] (a repeatable list of libraries (SWCs) to completely include in the SWF).</dd>
<dt><strong>rsl (Runtime Shared Library)</strong></dt>
<dd>Relevant only for Flex and AIR Applications (not SWCs or ActionScript 3 projects), this ensures that the library referenced by the SWF will be loaded once into the user's Flash Player cache at runtime. This is enabled by default on Flex projects for the framework dependencies (you can use static-link-runtime-shared-libraries on mxmlc to disable it).</dd>
<dt><strong>caching (Adobe Signed Runtime Shared Library)</strong></dt>
<dd>Like rsl except those library are signed.</dd>
<dt><strong>theme</strong></dt>
<dd>To indicate that dependency is a theme.</dd>
</dl>

Unfortunately Maven doesn't not support those scopes by default, generating warnings at build time.

This Maven extension enhances the default Maven model validation to allow those scopes.

To use it, place the generated jar-file to ${MAVEN_HOME}/lib/ext

or insert this auto activated profile in your pom to auto include it in ${MAVEN_HOME}/lib/ext, if the extension is not present, it will install it from your repository:

```
<profile>
    <id>prepare-maven-extended-libs</id>
    <activation>
        <file>
            <missing>${maven.home}/lib/ext/flexmojos-compatible-model-validator.jar</missing>
        </file>
    </activation>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-dependency-plugin</artifactId>
                <version>2.8</version>
                <executions>
                    <execution>
                        <id>copy</id>
                        <phase>validate</phase>
                        <goals>
                            <goal>copy</goal>
                        </goals>
                        <configuration>
                            <artifactItems>
                                <artifactItem>
                                    <groupId>com.doublefx.maven.utils.flexmojos</groupId>
                                    <artifactId>flexmojos-compatible-model-validator</artifactId>
                                    <version>1.0.0-SNAPSHOT</version>
                                    <type>jar</type>
                                    <overWrite>true</overWrite>
                                    <outputDirectory>${env.MAVEN_HOME}/lib/ext</outputDirectory>
                                </artifactItem>
                            </artifactItems>
                            <outputDirectory>${project.build.directory}/wars</outputDirectory>
                            <overWriteReleases>true</overWriteReleases>
                            <overWriteSnapshots>true</overWriteSnapshots>
                            <destFileName>flexmojos-compatible-model-validator.jar</destFileName>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <groupId>org.codehaus.gmaven</groupId>
                <artifactId>gmaven-plugin</artifactId>
                <version>1.4</version>
                <executions>
                    <execution>
                        <phase>validate</phase>
                        <goals>
                            <goal>execute</goal>
                        </goals>
                    </execution>
                </executions>
                <configuration>
                    <source>
                        fail("FlexMojos Compatible Model Validator extension is now configured. Please restart the build, and then it will be successful.")
                    </source>
                </configuration>
            </plugin>
        </plugins>
    </build>
</profile>
```
