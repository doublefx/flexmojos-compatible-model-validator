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
import java.nio.file.Files;
import java.util.List;

/**
 * Created by DoubleFx on 07/12/2014.
 */
@Component(role = AbstractMavenLifecycleParticipant.class, hint = "mavenExtensionInstallHelper")
public class FlexMojosExtensionInstallationHelper extends AbstractMavenLifecycleParticipant {
    @Requirement
    private Logger logger;

    @Requirement
    private RepositorySystem repoSystem;

    public void afterProjectsRead(MavenSession session) throws MavenExecutionException {
        copyExtension(session, "com.doublefx.maven.utils.flexmojos:flexmojos-compatible-model-validator:1.0.0-SNAPSHOT");
    }

    protected void copyExtension(MavenSession session, String artifactCoords) throws MavenExecutionException {
        Artifact artifact;
        try {
            artifact = new DefaultArtifact(artifactCoords);
        } catch (IllegalArgumentException e) {
            throw newMavenExecutionException(e);
        }
        ArtifactRequest request = new ArtifactRequest();
        request.setArtifact(artifact);
        final List<RemoteRepository> remoteRepos = session.getCurrentProject().getRemoteProjectRepositories();
        request.setRepositories(remoteRepos);
        logger.info("Resolving artifact " + artifact + " from " + remoteRepos);
        ArtifactResult result;
        try {
            result = repoSystem.resolveArtifact(session.getRepositorySession(), request);
        } catch (ArtifactResolutionException e) {
            throw newMavenExecutionException(e);
        }
        final Artifact resultArtifact = result.getArtifact();

        logger.info("Resolved artifact " + artifact + " to " + resultArtifact.getFile() + " from "
                + result.getRepository());

        final String maven_home = System.getenv("MAVEN_HOME").replace("\\", "/");
        final File destination = new File(maven_home + "/lib/ext/" + resultArtifact.getArtifactId() + ".jar");

        if (!destination.exists()) {
            try {
                Files.copy(resultArtifact.getFile().toPath(), destination.toPath());
            } catch (IOException ignored) {
            }
            throw newMavenExecutionException(new Exception(resultArtifact.getArtifactId() + " is now configured, please restart your build."));
        }
    }

    private static MavenExecutionException newMavenExecutionException(Exception cause) {
        return new MavenExecutionException(cause.getMessage(), cause);
    }
}
