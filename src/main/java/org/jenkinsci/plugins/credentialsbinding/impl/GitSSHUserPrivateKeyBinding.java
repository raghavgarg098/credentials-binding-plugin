/*
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.credentialsbinding.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.google.common.collect.ImmutableSet;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import java.io.File;
import java.io.PrintWriter;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

public class GitSSHUserPrivateKeyBinding extends MultiBinding<SSHUserPrivateKey> {

  String gitExe;
  public final String keyFileVariable;
  public String usernameVariable;
  public String passphraseVariable;
  private String encoding;
  TaskListener listener;


  @DataBoundConstructor public GitSSHUserPrivateKeyBinding(@Nonnull String keyFileVariable, String credentialsId) {
    super(credentialsId);
    this.keyFileVariable = keyFileVariable;
  }

  @DataBoundSetter
  public void setUsernameVariable(@Nonnull final String usernameVariable) {
    this.usernameVariable = usernameVariable;
  }

  @CheckForNull
  public String getUsernameVariable() {
    return usernameVariable;
  }

  @DataBoundSetter
  public void setPassphraseVariable(@Nonnull final String passphraseVariable) {
    this.passphraseVariable = passphraseVariable;
  }

  @CheckForNull
  public String getPassphraseVariable() {
    return passphraseVariable;
  }

  @Override protected Class<SSHUserPrivateKey> type() {
    return SSHUserPrivateKey.class;
  }

  @Override public Set<String> variables() {
    Set<String> set = new HashSet<>();
    set.add(keyFileVariable);
    if (usernameVariable != null) {
      set.add(usernameVariable);
    }
    if (passphraseVariable != null) {
      set.add(passphraseVariable);
    }
    return ImmutableSet.copyOf(set);
  }

  @Override public MultiEnvironment bind(Run<?,?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
    SSHUserPrivateKey sshKey = getCredentials(build);
    UnbindableDir keyDir = UnbindableDir.create(workspace);
    FilePath keyFile =  keyDir.getDirPath().child("ssh-key-" + keyFileVariable);

    StringBuilder contents = new StringBuilder();
    for (String key : sshKey.getPrivateKeys()) {
      contents.append(key);
      contents.append('\n');
    }
    keyFile.write(contents.toString(), "UTF-8");
    keyFile.chmod(0777);
    File ssh;
    File passphrase = null;
    File askpass = null;
    passphrase = createPassphraseFile(sshKey, keyFile);
    if (launcher.isUnix()) {
       ssh = createUnixGitSSH(keyFile, sshKey.getUsername());
       askpass =  createUnixSshAskpass(passphrase);
    }
    else
    {
      ssh = createWindowsGitSSH(keyFile, sshKey.getUsername());
      askpass =  createWindowsSshAskpass(passphrase);
    }

    Map<String, String> map = new LinkedHashMap<>();
    map.put(keyFileVariable, keyFile.getRemote());
    map.put("GIT_SSH", ssh.toString());
    map.put("GIT_SSH_VARIANT", "ssh");
    if (passphraseVariable != null) {
      if (sshKey.getPassphrase() != null) {
        map.put(passphraseVariable, sshKey.getPassphrase().getPlainText());
        map.put("SSH_ASKPASS", askpass.getAbsolutePath());
      } else {
        map.put(passphraseVariable, "");
      }
    }
    if (usernameVariable != null) {
      map.put(usernameVariable, sshKey.getUsername());
    }

    return new MultiEnvironment(map, keyDir.getUnbinder());
  }

  @Symbol("gitSshUserPrivateKey")
  @Extension public static class DescriptorImpl extends BindingDescriptor<SSHUserPrivateKey> {

    @Override protected Class<SSHUserPrivateKey> type() {
      return SSHUserPrivateKey.class;
    }

    @Override public String getDisplayName() {
      return Messages.GitSSHUserPrivateKeyBinding_git_ssh_user_private_key();
    }

  }

  private File getFileFromEnv(String envVar, String suffix) {
    String envValue = System.getenv(envVar);
    if (envValue == null) {
      return null;
    }
    return new File(envValue + suffix);
  }

  private File getSSHExeFromGitExeParentDir(String userGitExe) {
    String parentPath = new File(userGitExe).getParent();
    if (parentPath == null) {
      return null;
    }
    return new File(parentPath + "\\ssh.exe");
  }

  private String getPathToExe(String userGitExe) {
    userGitExe = userGitExe.toLowerCase(Locale.ENGLISH); // Avoid the Turkish 'i' conversion

    String cmd;
    String exe;
    if (userGitExe.endsWith(".exe")) {
      cmd = userGitExe.replace(".exe", ".cmd");
      exe = userGitExe;
    } else if (userGitExe.endsWith(".cmd")) {
      cmd = userGitExe;
      exe = userGitExe.replace(".cmd", ".exe");
    } else {
      cmd = userGitExe + ".cmd";
      exe = userGitExe + ".exe";
    }

    String[] pathDirs = System.getenv("PATH").split(File.pathSeparator);

    for (String pathDir : pathDirs) {
      File exeFile = new File(pathDir, exe);
      if (exeFile.exists()) {
        return exeFile.getAbsolutePath();
      }
      File cmdFile = new File(pathDir, cmd);
      if (cmdFile.exists()) {
        return cmdFile.getAbsolutePath();
      }
    }

    File userGitFile = new File(userGitExe);
    if (userGitFile.exists()) {
      return userGitFile.getAbsolutePath();
    }

    return null;
  }



  /* package */ File getSSHExecutable() {
    // First check the GIT_SSH environment variable
    File sshexe = getFileFromEnv("GIT_SSH", "");
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }

    // Check Program Files
    sshexe = getFileFromEnv("ProgramFiles", "\\Git\\bin\\ssh.exe");
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }
    sshexe = getFileFromEnv("ProgramFiles", "\\Git\\usr\\bin\\ssh.exe");
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }

    // Check Program Files(x86) for 64 bit computer
    sshexe = getFileFromEnv("ProgramFiles(x86)", "\\Git\\bin\\ssh.exe");
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }
    sshexe = getFileFromEnv("ProgramFiles(x86)", "\\Git\\usr\\bin\\ssh.exe");
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }

    // Search for an ssh.exe near the git executable.
    sshexe = getSSHExeFromGitExeParentDir(gitExe);
    if (sshexe != null && sshexe.exists()) {
      return sshexe;
    }

    // Search for git on the PATH, then look near it
    String gitPath = getPathToExe(gitExe);
    if (gitPath != null) {
      sshexe = getSSHExeFromGitExeParentDir(gitPath.replace("/bin/", "/usr/bin/").replace("\\bin\\", "\\usr\\bin\\"));
      if (sshexe != null && sshexe.exists()) {
        return sshexe;
      }
      // In case we are using msysgit from the cmd directory
      // instead of the bin directory, replace cmd with bin in
      // the path while trying to find ssh.exe.
      sshexe = getSSHExeFromGitExeParentDir(gitPath.replace("/cmd/", "/bin/").replace("\\cmd\\", "\\bin\\"));
      if (sshexe != null && sshexe.exists()) {
        return sshexe;
      }
      sshexe = getSSHExeFromGitExeParentDir(gitPath.replace("/cmd/", "/usr/bin/").replace("\\cmd\\", "\\usr\\bin\\"));
      if (sshexe != null && sshexe.exists()) {
        return sshexe;
      }
      sshexe = getSSHExeFromGitExeParentDir(gitPath.replace("/mingw64/", "/").replace("\\mingw64\\", "\\"));
      if (sshexe != null && sshexe.exists()) {
        return sshexe;
      }
      sshexe = getSSHExeFromGitExeParentDir(gitPath.replace("/mingw64/bin/", "/usr/bin/").replace("\\mingw64\\bin\\", "\\usr\\bin\\"));
      if (sshexe != null && sshexe.exists()) {
        return sshexe;
      }
    }

    throw new RuntimeException("ssh executable not found. The git plugin only supports official git client http://git-scm.com/download/win");
  }

  private File createPassphraseFile(SSHUserPrivateKey sshUser, FilePath keyFile) throws IOException {
    File passphraseFile =new File(keyFile.toString() + "_passphrase.txt");
    try (PrintWriter w = new PrintWriter(passphraseFile, "UTF-8"))
    {
      w.println(Secret.toString(sshUser.getPassphrase()));

    }
    return passphraseFile;
  }

  private String unixArgEncodeFileName(String filename) {
    if (filename.contains("'")) {
      filename = filename.replace("'", "'\\''");
    }
    return "'" + filename + "'";
  }

  private String windowsArgEncodeFileName(String filename) {
    if (filename.contains("\"")) {
      filename = filename.replace("\"", "^\"");
    }
    return "\"" + filename + "\"";
  }



  private File createUnixSshAskpass(File key) throws IOException {
    File pass = new File(key.toString(), "pass-copy");
    try (PrintWriter w = new PrintWriter(pass, "UTF-8")) {
      w.println("#!/bin/sh");
      w.println("cat " + unixArgEncodeFileName(key.toString()));
    }
    pass.setExecutable(true, true);
    return pass;
  }

  private File createUnixGitSSH(FilePath key, String user) throws IOException {
    File ssh = new File(key.toString() + "-copy");
    boolean isCopied = false;
    try (PrintWriter w = new PrintWriter(ssh, "UTF-8")) {
      w.println("#!/bin/sh");
      // ${SSH_ASKPASS} might be ignored if ${DISPLAY} is not set
      w.println("if [ -z \"${DISPLAY}\" ]; then");
      w.println("  DISPLAY=:123.456");
      w.println("  export DISPLAY");
      w.println("fi");
      w.println("ssh -i \"" + key.toString() + "\" -l \"" + user + "\" -o StrictHostKeyChecking=no \"$@\"");
    }
    ssh.setExecutable(true, true);
    return ssh;
  }


  private File createWindowsSshAskpass(File key) throws IOException {
    File ssh = new File(key.toString(), "pass-copy.bat");
    try (PrintWriter w = new PrintWriter(ssh, "UTF-8"))
    {
      // avoid echoing command as part of the password
      w.println("@echo off");
      w.println("type " + windowsArgEncodeFileName(key.toString()));
    }
    ssh.setExecutable(true, true);
    return ssh;
  }

  private File createWindowsGitSSH(FilePath key, String user) throws IOException {
    File ssh = new File(key.toString() + "-copy.bat");

    File sshexe = getSSHExecutable();

    try (PrintWriter w = new PrintWriter(ssh, "UTF-8")) {
      w.println("@echo off");
      w.println("\"" + sshexe.getAbsolutePath() + "\" -i \"" + key.toString() +"\" -l \"" + user + "\" -o StrictHostKeyChecking=no %* ");
    }
    ssh.setExecutable(true, true);
    return ssh;
  }
}
