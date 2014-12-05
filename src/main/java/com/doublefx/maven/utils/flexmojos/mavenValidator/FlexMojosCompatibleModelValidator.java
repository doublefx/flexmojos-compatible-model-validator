/*
 * Copyright (c) 2014 Frédéric Thomas
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.doublefx.maven.utils.flexmojos.mavenValidator;

import org.apache.maven.model.*;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.model.building.ModelProblem.Severity;
import org.apache.maven.model.building.ModelProblemCollector;
import org.apache.maven.model.validation.DefaultModelValidator;
import org.apache.maven.model.validation.ModelValidator;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.util.StringUtils;

import java.io.File;
import java.util.*;

@Component(role = ModelValidator.class)
public class FlexMojosCompatibleModelValidator extends DefaultModelValidator {

    private static final String ID_REGEX = "[A-Za-z0-9_\\-.]+";
    private static final String ILLEGAL_FS_CHARS = "\\/:\"<>|?*";
    private static final String ILLEGAL_VERSION_CHARS = ILLEGAL_FS_CHARS;

    @Override
    public void validateEffectiveModel( Model model, ModelBuildingRequest request, ModelProblemCollector problems )
    {
        validateStringNotEmpty("modelVersion", problems, Severity.ERROR, model.getModelVersion(), model);

        validateId("groupId", problems, model.getGroupId(), model);

        validateId("artifactId", problems, model.getArtifactId(), model);

        validateStringNotEmpty("packaging", problems, Severity.ERROR, model.getPackaging(), model);

        if ( !model.getModules().isEmpty() )
        {
            if ( !"pom".equals( model.getPackaging() ) )
            {
                addViolation( problems, Severity.ERROR, "packaging", null, "with value '" + model.getPackaging()
                        + "' is invalid. Aggregator projects " + "require 'pom' as packaging.", model );
            }

            for ( int i = 0, n = model.getModules().size(); i < n; i++ )
            {
                String module = model.getModules().get( i );
                if ( StringUtils.isBlank( module ) )
                {
                    addViolation( problems, Severity.WARNING, "modules.module[" + i + "]", null,
                            "has been specified without a path to the project directory.",
                            model.getLocation( "modules" ) );
                }
            }
        }

        validateStringNotEmpty("version", problems, Severity.ERROR, model.getVersion(), model);

        Severity errOn30 = getSeverity( request, ModelBuildingRequest.VALIDATION_LEVEL_MAVEN_3_0 );

        validateEffectiveDependencies(problems, model.getDependencies(), false, request);

        DependencyManagement mgmt = model.getDependencyManagement();
        if ( mgmt != null )
        {
            validateEffectiveDependencies(problems, mgmt.getDependencies(), true, request);
        }

        if ( request.getValidationLevel() >= ModelBuildingRequest.VALIDATION_LEVEL_MAVEN_2_0 )
        {
            Set<String> modules = new HashSet<String>();
            for ( int i = 0, n = model.getModules().size(); i < n; i++ )
            {
                String module = model.getModules().get( i );
                if ( !modules.add( module ) )
                {
                    addViolation( problems, Severity.ERROR, "modules.module[" + i + "]", null,
                            "specifies duplicate child module " + module, model.getLocation( "modules" ) );
                }
            }

            Severity errOn31 = getSeverity( request, ModelBuildingRequest.VALIDATION_LEVEL_MAVEN_3_1 );

            validateBannedCharacters( "version", problems, errOn31, model.getVersion(), null, model,
                    ILLEGAL_VERSION_CHARS );

            Build build = model.getBuild();
            if ( build != null )
            {
                for ( Plugin p : build.getPlugins() )
                {
                    validateStringNotEmpty( "build.plugins.plugin.artifactId", problems, Severity.ERROR,
                            p.getArtifactId(), p );

                    validateStringNotEmpty( "build.plugins.plugin.groupId", problems, Severity.ERROR, p.getGroupId(),
                            p );

                    validatePluginVersion( "build.plugins.plugin.version", problems, p.getVersion(), p.getKey(), p,
                            request );

                    validateBoolean( "build.plugins.plugin.inherited", problems, errOn30, p.getInherited(), p.getKey(),
                            p );

                    validateBoolean( "build.plugins.plugin.extensions", problems, errOn30, p.getExtensions(),
                            p.getKey(), p );

                    validateEffectivePluginDependencies( problems, p, request );
                }

                validateResources( problems, build.getResources(), "build.resources.resource", request );

                validateResources( problems, build.getTestResources(), "build.testResources.testResource", request );
            }

            Reporting reporting = model.getReporting();
            if ( reporting != null )
            {
                for ( ReportPlugin p : reporting.getPlugins() )
                {
                    validateStringNotEmpty( "reporting.plugins.plugin.artifactId", problems, Severity.ERROR,
                            p.getArtifactId(), p );

                    validateStringNotEmpty( "reporting.plugins.plugin.groupId", problems, Severity.ERROR,
                            p.getGroupId(), p );

                    validateStringNotEmpty( "reporting.plugins.plugin.version", problems, errOn31, p.getVersion(),
                            p.getKey(), p );
                }
            }

            for ( Repository repository : model.getRepositories() )
            {
                validateRepository( problems, repository, "repositories.repository", request );
            }

            for ( Repository repository : model.getPluginRepositories() )
            {
                validateRepository( problems, repository, "pluginRepositories.pluginRepository", request );
            }

            DistributionManagement distMgmt = model.getDistributionManagement();
            if ( distMgmt != null )
            {
                if ( distMgmt.getStatus() != null )
                {
                    addViolation( problems, Severity.ERROR, "distributionManagement.status", null,
                            "must not be specified.", distMgmt );
                }

                validateRepository(problems, distMgmt.getRepository(), "distributionManagement.repository", request);
                validateRepository(problems, distMgmt.getSnapshotRepository(),
                        "distributionManagement.snapshotRepository", request);
            }
        }
    }

    private void validateEffectiveDependencies(ModelProblemCollector problems, List<Dependency> dependencies, boolean management, ModelBuildingRequest request) {
        Severity errOn30 = getSeverity(request, 30);
        String prefix = management ? "dependencyManagement.dependencies.dependency." : "dependencies.dependency.";

        for (Dependency d : dependencies) {
            this.validateEffectiveDependency(problems, d, management, prefix, request);
            if (request.getValidationLevel() >= 20) {
                this.validateBoolean(prefix + "optional", problems, errOn30, d.getOptional(), d.getManagementKey(), d);
                if (!management) {
                    this.validateVersion(prefix + "version", problems, errOn30, d.getVersion(), d.getManagementKey(), d);
                    this.validateEnum(prefix + "scope", problems, Severity.WARNING, d.getScope(), d.getManagementKey(), d, "merged", "external", "internal", "caching", "rsl", "theme", "provided", "compile", "runtime", "test", "system");
                }
            }
        }

    }

    private void validateEffectivePluginDependencies(ModelProblemCollector problems, Plugin plugin, ModelBuildingRequest request) {
        List<Dependency> dependencies = plugin.getDependencies();
        if (!dependencies.isEmpty()) {
            String prefix = "build.plugins.plugin[" + plugin.getKey() + "].dependencies.dependency.";
            Severity errOn30 = getSeverity(request, 30);

            for (Dependency d : dependencies) {
                this.validateEffectiveDependency(problems, d, false, prefix, request);
                this.validateVersion(prefix + "version", problems, errOn30, d.getVersion(), d.getManagementKey(), d);
                this.validateEnum(prefix + "scope", problems, errOn30, d.getScope(), d.getManagementKey(), d, "compile", "runtime", "system");
            }
        }

    }

    private void validateEffectiveDependency(ModelProblemCollector problems, Dependency d, boolean management, String prefix, ModelBuildingRequest request) {
        this.validateId(prefix + "artifactId", problems, Severity.ERROR, d.getArtifactId(), d.getManagementKey(), d);
        this.validateId(prefix + "groupId", problems, Severity.ERROR, d.getGroupId(), d.getManagementKey(), d);
        if (!management) {
            this.validateStringNotEmpty(prefix + "type", problems, Severity.ERROR, d.getType(), d.getManagementKey(), d);
            this.validateStringNotEmpty(prefix + "version", problems, Severity.ERROR, d.getVersion(), d.getManagementKey(), d);
        }

        if ("system".equals(d.getScope())) {
            String i$ = d.getSystemPath();
            if (StringUtils.isEmpty(i$)) {
                addViolation(problems, Severity.ERROR, prefix + "systemPath", d.getManagementKey(), "is missing.", d);
            } else {
                File exclusion = new File(i$);
                if (!exclusion.isAbsolute()) {
                    addViolation(problems, Severity.ERROR, prefix + "systemPath", d.getManagementKey(), "must specify an absolute path but is " + i$, d);
                } else if (!exclusion.isFile()) {
                    String msg = "refers to a non-existing file " + exclusion.getAbsolutePath();
                    i$ = i$.replace('/', File.separatorChar).replace('\\', File.separatorChar);
                    String jdkHome = request.getSystemProperties().getProperty("java.home", "") + File.separator + "..";
                    if (i$.startsWith(jdkHome)) {
                        msg = msg + ". Please verify that you run Maven using a JDK and not just a JRE.";
                    }

                    addViolation(problems, Severity.WARNING, prefix + "systemPath", d.getManagementKey(), msg, d);
                }
            }
        } else if (StringUtils.isNotEmpty(d.getSystemPath())) {
            addViolation(problems, Severity.ERROR, prefix + "systemPath", d.getManagementKey(), "must be omitted. This field may only be specified for a dependency with system scope.", d);
        }

        if (request.getValidationLevel() >= 20) {

            for (Exclusion exclusion1 : d.getExclusions()) {
                this.validateId(prefix + "exclusions.exclusion.groupId", problems, Severity.WARNING, exclusion1.getGroupId(), d.getManagementKey(), exclusion1);
                this.validateId(prefix + "exclusions.exclusion.artifactId", problems, Severity.WARNING, exclusion1.getArtifactId(), d.getManagementKey(), exclusion1);
            }
        }

    }

    private void validateRepository(ModelProblemCollector problems, Repository repository, String prefix, ModelBuildingRequest request) {
        if (repository != null) {
            Severity errOn31 = getSeverity(request, 31);
            this.validateBannedCharacters(prefix + ".id", problems, errOn31, repository.getId(), null, repository, "\\/:\"<>|?*");
            if ("local".equals(repository.getId())) {
                addViolation(problems, errOn31, prefix + ".id", null, "must not be \'local\', this identifier is reserved for the local repository, using it for other repositories will corrupt your repository metadata.", repository);
            }

            if ("legacy".equals(repository.getLayout())) {
                addViolation(problems, Severity.WARNING, prefix + ".layout", repository.getId(), "uses the unsupported value \'legacy\', artifact resolution might fail.", repository);
            }
        }

    }

    private void validateResources(ModelProblemCollector problems, List<Resource> resources, String prefix, ModelBuildingRequest request) {
        Severity errOn30 = getSeverity(request, 30);

        for (Resource resource : resources) {
            this.validateStringNotEmpty(prefix + ".directory", problems, Severity.ERROR, resource.getDirectory(), resource);
            this.validateBoolean(prefix + ".filtering", problems, errOn30, resource.getFiltering(), resource.getDirectory(), resource);
        }

    }

    private boolean validateId(String fieldName, ModelProblemCollector problems, String id, InputLocationTracker tracker) {
        return this.validateId(fieldName, problems, Severity.ERROR, id, null, tracker);
    }

    private boolean validateId(String fieldName, ModelProblemCollector problems, Severity severity, String id, String sourceHint, InputLocationTracker tracker) {
        if (!this.validateStringNotEmpty(fieldName, problems, severity, id, sourceHint, tracker)) {
            return false;
        } else {
            boolean match = id.matches(ID_REGEX);
            if (!match) {
                addViolation(problems, severity, fieldName, sourceHint, "with value \'" + id + "\' does not match a valid id pattern.", tracker);
            }

            return match;
        }
    }

    private boolean hasExpression(String value) {
        return value != null && value.contains("${");
    }

    private boolean validateStringNotEmpty(String fieldName, ModelProblemCollector problems, Severity severity, String string, InputLocationTracker tracker) {
        return this.validateStringNotEmpty(fieldName, problems, severity, string, null, tracker);
    }

    private boolean validateStringNotEmpty(String fieldName, ModelProblemCollector problems, Severity severity, String string, String sourceHint, InputLocationTracker tracker) {
        if (!this.validateNotNull(fieldName, problems, severity, string, sourceHint, tracker)) {
            return false;
        } else if (string.length() > 0) {
            return true;
        } else {
            addViolation(problems, severity, fieldName, sourceHint, "is missing.", tracker);
            return false;
        }
    }

    private boolean validateNotNull(String fieldName, ModelProblemCollector problems, Severity severity, String object, String sourceHint, InputLocationTracker tracker) {
        if (object != null) {
            return true;
        } else {
            addViolation(problems, severity, fieldName, sourceHint, "is missing.", tracker);
            return false;
        }
    }

    private boolean validateBoolean(String fieldName, ModelProblemCollector problems, Severity severity, String string, String sourceHint, InputLocationTracker tracker) {
        if (string != null && string.length() > 0) {
            if (!"true".equalsIgnoreCase(string) && !"false".equalsIgnoreCase(string)) {
                addViolation(problems, severity, fieldName, sourceHint, "must be \'true\' or \'false\' but is \'" + string + "\'.", tracker);
                return false;
            } else {
                return true;
            }
        } else {
            return true;
        }
    }

    private boolean validateEnum(String fieldName, ModelProblemCollector problems, Severity severity, String string, String sourceHint, InputLocationTracker tracker, String... validValues) {
        if (string != null && string.length() > 0) {
            List<? extends String> values = Arrays.asList(validValues);
            if (values.contains(string)) {
                return true;
            } else {
                addViolation(problems, severity, fieldName, sourceHint, "must be one of " + values + " but is \'" + string + "\'.", tracker);
                return false;
            }
        } else {
            return true;
        }
    }

    private boolean validateBannedCharacters(String fieldName, ModelProblemCollector problems, Severity severity, String string, String sourceHint, InputLocationTracker tracker, String banned) {
        if (string != null) {
            for (int i = string.length() - 1; i >= 0; --i) {
                if (banned.indexOf(string.charAt(i)) >= 0) {
                    addViolation(problems, severity, fieldName, sourceHint, "must not contain any of these characters " + banned + " but found " + string.charAt(i), tracker);
                    return false;
                }
            }
        }

        return true;
    }

    private boolean validateVersion(String fieldName, ModelProblemCollector problems, Severity severity, String string, String sourceHint, InputLocationTracker tracker) {
        if (string != null && string.length() > 0) {
            if (!this.hasExpression(string)) {
                return true;
            } else {
                addViolation(problems, severity, fieldName, sourceHint, "must be a valid version but is \'" + string + "\'.", tracker);
                return false;
            }
        } else {
            return true;
        }
    }

    private boolean validatePluginVersion(String fieldName, ModelProblemCollector problems, String string, String sourceHint, InputLocationTracker tracker, ModelBuildingRequest request) {
        Severity errOn30 = getSeverity(request, 30);
        if (string == null) {
            return true;
        } else if (string.length() > 0 && !this.hasExpression(string) && !"RELEASE".equals(string) && !"LATEST".equals(string)) {
            return true;
        } else {
            addViolation(problems, errOn30, fieldName, sourceHint, "must be a valid version but is \'" + string + "\'.", tracker);
            return false;
        }
    }

    private static void addViolation(ModelProblemCollector problems, Severity severity, String fieldName, String sourceHint, String message, InputLocationTracker tracker) {
        StringBuilder buffer = new StringBuilder(256);
        buffer.append('\'').append(fieldName).append('\'');
        if (sourceHint != null) {
            buffer.append(" for ").append(sourceHint);
        }

        buffer.append(' ').append(message);
        problems.add(severity, buffer.toString(), getLocation(fieldName, tracker), null);
    }

    private static InputLocation getLocation(String fieldName, InputLocationTracker tracker) {
        InputLocation location = null;
        if (tracker != null) {
            if (fieldName != null) {
                java.io.Serializable key = fieldName;
                int idx = fieldName.lastIndexOf(46);
                if (idx >= 0) {
                    key = fieldName = fieldName.substring(idx + 1);
                }

                if (fieldName.endsWith("]")) {
                    key = fieldName.substring(fieldName.lastIndexOf(91) + 1, fieldName.length() - 1);

                    try {
                        key = Integer.valueOf(key.toString());
                    } catch (NumberFormatException ignored) {
                    }
                }

                location = tracker.getLocation(key);
            }

            if (location == null) {
                location = tracker.getLocation("");
            }
        }

        return location;
    }

    private static Severity getSeverity(ModelBuildingRequest request, int errorThreshold) {
        return getSeverity(request.getValidationLevel(), errorThreshold);
    }

    private static Severity getSeverity(int validationLevel, int errorThreshold) {
        return validationLevel < errorThreshold ? Severity.WARNING : Severity.ERROR;
    }
}
