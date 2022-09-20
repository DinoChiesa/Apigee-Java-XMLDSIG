// Copyright 2018-2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.xmldsig;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;
import mockit.Mock;
import mockit.MockUp;
import org.testng.annotations.BeforeMethod;

public class TestBase {
  private static final String testResourceDir = "src/test/resources";

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  InputStream messageContentStream;
  Message message;
  ExecutionContext exeCtxt;

  Boolean verbose = false; // true

  @BeforeMethod()
  public void beforeMethod() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String, Object> variables;

          public void $init() {
            variables = new HashMap<String, Object>();
          }

          @Mock()
          public Object getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            Object value = variables.get(name);
            if (verbose) {
              System.out.printf("getVariable(%s) => %s\n", name, value==null?"-null-":value.toString());
            }
            return value;
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            if (verbose) {
              System.out.printf("setVariable(%s) => %s\n", name, value==null?"-null-":value.toString());
            }
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            if (verbose) {
              System.out.printf("removeVariable(%s)\n", name );
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }

          @Mock()
          public Message getMessage() {
            return message;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();

    message =
        new MockUp<Message>() {
          @Mock()
          public InputStream getContentAsStream() {
            // new ByteArrayInputStream(messageContent.getBytes(StandardCharsets.UTF_8));
            return messageContentStream;
          }
        }.getMockInstance();
  }

  protected static String getResourceFileContents(String childDir, String filename) throws Exception {
    Path path = Paths.get(testResourceDir, childDir, filename);
    if (! Files.exists(path)) {
      return null;
    }
    return new String(Files.readAllBytes(path));
  }

  // @DataProvider requires the output to be a Object[][]. The inner
  // Object[] is the set of params that get passed to the test method.
  // So, if you want to pass just one param to the constructor, then
  // each inner Object[] must have length 1.

  protected Object[][] toDataProvider(String[] a) {
    ArrayList<Object[]> list = new ArrayList<Object[]>();

    IntStream.range(0, a.length)
      .forEach( i -> list.add(new Object[] { i, a[i] }));
    return list.toArray(new Object[list.size()][]);
  }

}
