package com.kerb4j.client;

import com.kerb4j.client.spi.SpnegoClientBackend;
import com.kerb4j.client.spi.SubjectBasedSpnegoClientBackend;
import org.ietf.jgss.GSSContext;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class SpnegoContextSubjectTest {

    @Test
    void createTokenAndProcessMutualAuthorizationUseCapturedSubjectAndDoNotRefreshClientSubject() throws Exception {
        Subject subjectA = new Subject();
        Subject subjectB = new Subject();
        CountingBackend backend = new CountingBackend(subjectA, subjectB);
        SpnegoClient spnegoClient = spnegoClient(backend);
        List<Subject> subjectsUsedByGssContext = new ArrayList<>();
        GSSContext gssContext = gssContext(subjectsUsedByGssContext, new ArrayList<>());

        SpnegoContext context = new SpnegoContext(spnegoClient, gssContext);

        context.createToken();
        context.processMutualAuthorization(new byte[]{2}, 0, 1);

        assertSame(subjectA, subjectsUsedByGssContext.get(0));
        assertSame(subjectA, subjectsUsedByGssContext.get(1));
        assertEquals(1, backend.subjectCalls.get());
    }

    @Test
    void acceptTokenUsesCapturedAcceptorSubject() throws Exception {
        Subject acceptorSubject = new Subject();
        List<Subject> subjectsUsedByGssContext = new ArrayList<>();
        GSSContext gssContext = gssContext(new ArrayList<>(), subjectsUsedByGssContext);

        SpnegoContext context = new SpnegoContext(acceptorSubject, gssContext);

        context.acceptToken(new byte[]{2});

        assertSame(acceptorSubject, subjectsUsedByGssContext.get(0));
    }

    @Test
    void alreadyCreatedContextKeepsFirstSupplierSubjectWhenBackendLaterRefreshes() throws Exception {
        Subject subjectA = new Subject();
        Subject subjectB = new Subject();
        AtomicInteger supplierCalls = new AtomicInteger();
        List<Subject> contextCreationSubjects = new ArrayList<>();
        List<Subject> subjectsUsedByGssContext = new ArrayList<>();
        GSSContext gssContext = gssContext(subjectsUsedByGssContext, new ArrayList<>());

        SubjectBasedSpnegoClientBackend backend = new SubjectBasedSpnegoClientBackend("test", () -> subjectA) {
            @Override
            public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn) {
                Subject subject = nextSubject();
                contextCreationSubjects.add(subject);
                return new SpnegoContext(spnegoClient, subject, gssContext);
            }

            @Override
            public Subject getSubject() {
                return nextSubject();
            }

            private Subject nextSubject() {
                return supplierCalls.incrementAndGet() == 1 ? subjectA : subjectB;
            }
        };

        SpnegoContext context = backend.createContextForSPN(null, "HTTP/service.example.com");
        Subject refreshedSubject = backend.getSubject();
        context.createToken();

        assertSame(subjectA, contextCreationSubjects.get(0));
        assertSame(subjectB, refreshedSubject);
        assertSame(subjectA, subjectsUsedByGssContext.get(0));
    }

    @Test
    void constructorRejectsMissingSubjectOrGssContext() {
        GSSContext gssContext = gssContext(new ArrayList<>(), new ArrayList<>());
        assertThrows(NullPointerException.class, () -> new SpnegoContext((Subject) null, gssContext));
        assertThrows(NullPointerException.class, () -> new SpnegoContext(new Subject(), null));
    }

    private static GSSContext gssContext(List<Subject> initSubjects, List<Subject> acceptSubjects) {
        return (GSSContext) Proxy.newProxyInstance(
                GSSContext.class.getClassLoader(),
                new Class[]{GSSContext.class},
                (proxy, method, args) -> {
                    if ("initSecContext".equals(method.getName()) && args != null && args.length == 3) {
                        initSubjects.add(currentSubject());
                        return new byte[]{1};
                    }
                    if ("acceptSecContext".equals(method.getName()) && args != null && args.length == 3) {
                        acceptSubjects.add(currentSubject());
                        return new byte[]{1};
                    }
                    if ("isEstablished".equals(method.getName())) {
                        return true;
                    }
                    if ("toString".equals(method.getName())) {
                        return "test-gss-context";
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive() || Void.TYPE.equals(type)) {
            return null;
        }
        if (Boolean.TYPE.equals(type)) {
            return false;
        }
        if (Character.TYPE.equals(type)) {
            return '\0';
        }
        return 0;
    }

    private static Subject currentSubject() {
        try {
            Method current = Subject.class.getMethod("current");
            return (Subject) current.invoke(null);
        } catch (ReflectiveOperationException e) {
            return Subject.getSubject(AccessController.getContext());
        }
    }

    private static SpnegoClient spnegoClient(SpnegoClientBackend backend) throws Exception {
        Constructor<SpnegoClient> constructor = SpnegoClient.class.getDeclaredConstructor(SpnegoClientBackend.class);
        constructor.setAccessible(true);
        return constructor.newInstance(backend);
    }

    private static class CountingBackend implements SpnegoClientBackend {
        private final AtomicInteger subjectCalls = new AtomicInteger();
        private final Subject[] subjects;

        private CountingBackend(Subject... subjects) {
            this.subjects = subjects;
        }

        @Override
        public String getImplementationName() {
            return "test";
        }

        @Override
        public Subject getSubject() {
            int index = Math.min(subjectCalls.getAndIncrement(), subjects.length - 1);
            return subjects[index];
        }

        @Override
        public javax.security.auth.kerberos.KerberosKey[] getKerberosKeys() {
            return null;
        }

        @Override
        public SpnegoContext createContext(SpnegoClient spnegoClient, URL url) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SpnegoContext createContextForSPN(SpnegoClient spnegoClient, String spn)
                throws MalformedURLException {
            throw new UnsupportedOperationException();
        }

        @Override
        public SpnegoContext createAcceptContext(SpnegoClient spnegoClient) {
            throw new UnsupportedOperationException();
        }
    }
}
