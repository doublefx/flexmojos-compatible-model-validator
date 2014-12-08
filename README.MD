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

Unfortunately Maven doesn't support those scopes by default, generating warnings at build time.

This Maven extension enhances the default Maven model validation to allow those scopes.

To use it, place the generated jar-file without the version number into ${MAVEN_HOME}/lib/ext or add the extension to your parent project pom.xml (the first build will install the extension, the next ones will use it) or even better, to your corporate pom.xml, doing so, it will be used from the first build.

```
<build>
    <extensions>
        <extension>
            <groupId>com.doublefx.maven.utils.flexmojos</groupId>
            <artifactId>flexmojos-compatible-model-validator</artifactId>
            <version>1.0.0-SNAPSHOT</version>
        </extension>
    </extensions>
    ...
```
