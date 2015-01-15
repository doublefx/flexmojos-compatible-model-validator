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

import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenSession;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.logging.Logger;
import org.sonatype.aether.RepositorySystem;
import org.sonatype.aether.artifact.Artifact;
import org.sonatype.aether.repository.RemoteRepository;
import org.sonatype.aether.resolution.ArtifactRequest;
import org.sonatype.aether.resolution.ArtifactResolutionException;
import org.sonatype.aether.resolution.ArtifactResult;
import org.sonatype.aether.util.artifact.DefaultArtifact;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Properties;

@Component(role = AbstractMavenLifecycleParticipant.class, hint = "mavenExtensionInstallHelper")
public class FlexMojosExtensionInstallationHelper extends AbstractMavenLifecycleParticipant {

    private static final String GROUP_ID = "com.doublefx.maven.utils.flexmojos";
    private static final String ARTIFACT_ID = "flexmojos-compatible-model-validator";
    private static final String MINIMAL_VERSION = "1.0.0-SNAPSHOT";

    @Requirement
    private Logger logger;

    @Requirement
    private RepositorySystem repoSystem;

    public void afterProjectsRead(MavenSession session) throws MavenExecutionException {
        copyExtension(session, GROUP_ID + ":" + ARTIFACT_ID + ":" + getVersion());
    }

    protected void copyExtension(MavenSession session, String artifactCoordinates) throws MavenExecutionException {
        Artifact artifact;
        try {
            artifact = new DefaultArtifact(artifactCoordinates);
        } catch (IllegalArgumentException e) {
            throw newMavenExecutionException(e);
        }

        ArtifactRequest request = new ArtifactRequest();
        request.setArtifact(artifact);

        final List<RemoteRepository> remoteRepos = session.getCurrentProject().getRemoteProjectRepositories();

        request.setRepositories(remoteRepos);

        ArtifactResult result;
        try {
            result = repoSystem.resolveArtifact(session.getRepositorySession(), request);
        } catch (ArtifactResolutionException e) {
            logger.info("Resolving artifact " + artifact + " from " + remoteRepos);
            throw newMavenExecutionException(e);
        }

        final Artifact resultArtifact = result.getArtifact();

        final String maven_home = System.getenv("MAVEN_HOME");
        final File destination = new File(maven_home + File.separator + "lib" + File.separator + "ext" + File.separator + resultArtifact.getArtifactId() + ".jar");

        if (!destination.exists()) {
            logger.info("Resolved artifact " + artifact + " to " + resultArtifact.getFile() + " from "
                    + result.getRepository());

            try {
                Files.copy(resultArtifact.getFile().toPath(), destination.toPath());
            } catch (IOException ignored) {}

            logger.info(resultArtifact.getArtifactId() + " is now configured, it will be applied to your next builds.");
        }
    }

    public String getVersion() {
        String version = null;

        // try to load from maven properties first
        try {
            Properties p = new Properties();
            InputStream is = getClass().getResourceAsStream("/META-INF/maven/" + GROUP_ID + "/" + ARTIFACT_ID + "/pom.properties");
            if (is != null) {
                p.load(is);
                version = p.getProperty("version", "");
            }
        } catch (Exception e) {
            // ignore
        }

        // fallback to using Java API
        if (version == null) {
            Package aPackage = getClass().getPackage();
            if (aPackage != null) {
                version = aPackage.getImplementationVersion();
                if (version == null) {
                    version = aPackage.getSpecificationVersion();
                }
            }
        }

        if (version == null) {
            // we could not compute the version so use the minimal one.
            version = MINIMAL_VERSION;
        }

        return version;
    }

    private static MavenExecutionException newMavenExecutionException(Exception cause) {
        return new MavenExecutionException(cause.getMessage(), cause);
    }
}
