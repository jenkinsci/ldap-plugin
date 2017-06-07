/*
 * The MIT License
 *
 * Copyright 2017 CloudBees,Inc.
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

package jenkins.security.plugins.ldap;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.csn.CsnFactory;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.comparators.NormalizingComparator;
import org.apache.directory.api.ldap.model.schema.registries.ComparatorRegistry;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.factory.JdbmPartitionFactory;
import org.apache.directory.server.core.factory.PartitionFactory;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.junit.rules.MethodRule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;

/**
 * Starts an embedded LDAP server.
 */
public class LDAPRule implements TestRule, MethodRule {
    private static final Logger LOGGER = Logger.getLogger(LDAPRule.class.getName());
    /**
     * The directory service
     */
    private DirectoryService service;

    /**
     * The partition factory.
     */
    private PartitionFactory factory;

    /**
     * The LDAP server
     */
    private LdapServer server;

    /**
     * The work directory for the ldap server.
     */
    private File workDir;

    private LDAPTestConfiguration configuration;
    private LDAPSchema ldapSchema;
    private Description currentTest;

    public int getPort() {
        if (server == null || !server.isStarted()) {
            throw new IllegalStateException("LDAP server not started");
        }
        for (Transport t : server.getTransports()) {
            if (t instanceof TcpTransport && !t.isSSLEnabled()) {
                return ((TcpTransport) t).getAcceptor().getLocalAddress().getPort();
            }
        }
        return -1;
    }

    public int getPortTls() {
        if (server == null || !server.isStarted()) {
            throw new IllegalStateException("LDAP server not started");
        }
        for (Transport t : server.getTransports()) {
            if (t instanceof TcpTransport && t.isSSLEnabled()) {
                return ((TcpTransport) t).getAcceptor().getLocalAddress().getPort();
            }
        }
        return -1;
    }

    public String getUrl() {
        try {
            int port = getPort();
            if (port == -1) {
                throw new IllegalStateException("LDAP protocol not enabled");
            }
            return new URI("ldap", null, "localhost", port, null, null, null).toString();
        } catch (URISyntaxException e) {
            throw new AssertionError(e);
        }
    }

    public String getUrlTls() {
        try {
            int port = getPortTls();
            if (port == -1) {
                throw new IllegalStateException("LDAPS protocol not enabled");
            }
            return new URI("ldaps", null, "localhost", getPortTls(), null, null, null).toString();
        } catch (URISyntaxException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public Statement apply(Statement base, FrameworkMethod method, Object target) {
        return this.apply(base,
                Description.createTestDescription(
                        method.getMethod().getDeclaringClass(),
                        method.getName(),
                        method.getAnnotations()
                )
        );
    }

    @Override
    public Statement apply(final Statement base, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                currentTest = description;
                configuration = description.getAnnotation(LDAPTestConfiguration.class);
                if (configuration == null) {
                    configuration = description.getTestClass().getAnnotation(LDAPTestConfiguration.class);
                }
                ldapSchema = description.getAnnotation(LDAPSchema.class);
                if (ldapSchema == null) {
                    ldapSchema = description.getTestClass().getAnnotation(LDAPSchema.class);
                }
                workDir = Files.createTempDirectory("ads-workdir").toFile();
                Logger adsLogger = Logger.getLogger("org.apache.directory");
                Level adsLevel = adsLogger.getLevel();
                try {
                    if (configuration != null && !configuration.logStartup()) {
                        adsLogger.setLevel(Level.SEVERE);
                    }
                    LOGGER.log(Level.INFO, "Starting LDAP server");
                    initDirectoryService(workDir);
                    try {
                        startServer();
                        try {
                            adsLogger.setLevel(adsLevel);
                            LOGGER.log(Level.INFO, "LDAP server started");
                            if (configuration == null || configuration.ldapProtocol()) {
                                LOGGER.log(Level.INFO, "LDAP URL: {0}", getUrl());
                            }
                            if (configuration != null && configuration.ldapsProtocol()) {
                                LOGGER.log(Level.INFO, "LDAP URL: {0}", getUrlTls());
                            }
                            base.evaluate();
                            if (configuration != null && !configuration.logStartup()) {
                                adsLogger.setLevel(Level.SEVERE);
                            }
                        } finally {
                            stopServer();
                        }
                    } finally {
                        termDirectoryService();
                    }
                } finally {
                    adsLogger.setLevel(adsLevel);
                    currentTest = null;
                    configuration = null;
                    ldapSchema = null;
                    FileUtils.deleteDirectory(workDir);
                }
            }
        };
    }

    private void termDirectoryService() throws Exception {
        service.shutdown();
        service = null;
    }

    public void stopServer() {
        server.stop();
        server = null;
    }

    /**
     * starts the LdapServer
     *
     * @throws Exception
     */
    public void startServer() throws Exception {
        server = new LdapServer();

        List<Transport> transports = new ArrayList<>();
        if (configuration == null || configuration.ldapProtocol()) {
            transports.add(new TcpTransport(0));
        }
        if (configuration != null && configuration.ldapsProtocol()) {
            TcpTransport tlsTransport;
            tlsTransport = new TcpTransport(0);
            tlsTransport.setEnableSSL(true);
            transports.add(tlsTransport);
        }
        server.setTransports(transports.toArray(new Transport[transports.size()]));
        server.setDirectoryService(service);
        server.start();
    }

    /**
     * Initialize the server. It creates the partition, adds the index, and
     * injects the context entries for the created partitions.
     *
     * @param workDir the directory to be used for storing the data
     * @throws Exception if there were some problems while initializing the system
     */
    private void initDirectoryService(File workDir) throws Exception {
        // Initialize the LDAP service
        service = new DefaultDirectoryService();
        service.setInstanceId(currentTest.getDisplayName());
        service.setInstanceLayout(new InstanceLayout(workDir));
        CacheService cacheService = new CacheService();
        cacheService.initialize(service.getInstanceLayout(), "test");
        service.setCacheService(cacheService);

        factory = new JdbmPartitionFactory();

        // first load the schema
        initSchema();

        // then the system partition
        // this is a MANDATORY partition
        initSystemPartition();

        // Disable the ChangeLog system
        service.getChangeLog().setEnabled(false);
        service.setDenormalizeOpAttrsEnabled(true);

        // Now we can create as many partitions as we need
        // Create some new partitions named 'foo', 'bar' and 'apache'.

        Partition partition;
        if (ldapSchema == null) {
            partition = addPartition("jenkins", "dc=jenkins,dc=io");
        } else {
            partition = addPartition(ldapSchema.id(), ldapSchema.dn());
        }

        // Index some attributes on the jenkins partition
        addIndex(partition, "objectClass", "ou", "uid");

        // And start the service
        service.startup();

        try {
            CoreSession coreSession = service.getAdminSession();
            ModifyRequest modifyRequest = new ModifyRequestImpl();
            modifyRequest.setName(new Dn("uid=admin", "ou=system"));
            modifyRequest.replace("userPassword", configuration == null ? "password" : configuration.adminPassword());
            coreSession.modify(modifyRequest);
        } catch (LdapException lnnfe) {
            throw new AssertionError("Could not update admin password");
        }

        if (ldapSchema != null) {
            String resourceName = ldapSchema.ldif() + ".ldif";
            String schemaSource = resourceName.startsWith("/")
                    ? resourceName
                    : currentTest.getTestClass().getName().replace('.', '/') + "/" + resourceName;
            try (InputStream stream = currentTest.getTestClass().getResourceAsStream(resourceName)) {
                LOGGER.log(Level.INFO, "Importing schema from {0}", schemaSource);
                loadSchema(partition, stream);
            }
        }

        // We are all done !
    }

    public void loadSchema(String partitionId, String partitionDn, InputStream ldifStream) throws Exception {
        loadSchema(addPartition(partitionId, partitionDn), ldifStream);
    }

    private void loadSchema(Partition partition, InputStream ldifStream) throws LdapException, IOException {
        try {
            service.getAdminSession().lookup(partition.getSuffixDn());
        } catch (LdapException lnnfe) {
            Entry entryBar = service.newEntry(partition.getSuffixDn());
            entryBar.add("objectClass", "top", "domain", "extensibleObject");
            entryBar.add("entryCSN", new CsnFactory(1).newInstance().toString());
            entryBar.add("entryUUID", UUID.randomUUID().toString());
            // not sure about the rest of this, may need tweaking but works for now
            entryBar.add("dc", partition.getSuffixDn().toString()); // will blow up without a dc
            service.getAdminSession().add(entryBar);
        }

        int created = 0;
        int skipped = 0;
        int modified = 0;
        CoreSession coreSession = service.getAdminSession();
        for (LdifEntry ldifEntry : new LdifReader(ldifStream)) {
            Dn dn = ldifEntry.getDn();

            if (ldifEntry.isEntry()) {
                Entry entry = ldifEntry.getEntry();

                try {
                    coreSession.lookup(dn);
                    LOGGER.log(Level.FINE, "Found {0}, will not create.", dn);
                    skipped++;
                } catch (Exception e) {
                    coreSession.add(
                            new DefaultEntry(
                                    coreSession.getDirectoryService().getSchemaManager(), entry));
                    LOGGER.log(Level.FINE, "Created {0}.", dn);
                    created++;
                }
            } else {
                //modify
                List<Modification> items = ldifEntry.getModifications();

                coreSession.modify(dn, items);
                LOGGER.log(Level.INFO, "Modified: {0} with modificationItems: {1}",
                        new Object[]{dn, items});
                modified += items.size();
            }
        }
        LOGGER.log(Level.INFO, "Schema imported -> created {0} modified {1} skipped {2}",
                new Object[]{
                        created, modified, skipped
                });
    }


    /**
     * Inits the schema and schema partition.
     */
    private void initSchema() throws Exception {
        File workingDirectory = service.getInstanceLayout().getPartitionsDirectory();

        // Extract the schema on disk (a brand new one) and load the registries
        File schemaRepository = new File(workingDirectory, "schema");
        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(workingDirectory);

        try {
            extractor.extractOrCopy();
        } catch (IOException ioe) {
            // The schema has already been extracted, bypass
        }

        SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        // Tell all the normalizer comparators that they should not normalize anything
        ComparatorRegistry comparatorRegistry = schemaManager.getComparatorRegistry();

        for (LdapComparator<?> comparator : comparatorRegistry) {
            if (comparator instanceof NormalizingComparator) {
                ((NormalizingComparator) comparator).setOnServer();
            }
        }

        service.setSchemaManager(schemaManager);

        // Init the LdifPartition
        LdifPartition ldifPartition = new LdifPartition(schemaManager, service.getDnFactory());
        ldifPartition.setPartitionPath(new File(workingDirectory, "schema").toURI());
        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(ldifPartition);
        service.setSchemaPartition(schemaPartition);

        List<Throwable> errors = schemaManager.getErrors();

        if (errors.size() != 0) {
            throw new Exception(I18n.err(I18n.ERR_317, Exceptions.printErrors(errors)));
        }
    }

    /**
     * Inits the system partition.
     *
     * @throws Exception the exception
     */
    private void initSystemPartition() throws Exception {
        // change the working directory to something that is unique
        // on the system and somewhere either under target directory
        // or somewhere in a temp area of the machine.

        // Inject the System Partition
        Partition systemPartition = factory.createPartition(service.getSchemaManager(),
                service.getDnFactory(),
                "system", ServerDNConstants.SYSTEM_DN, 500,
                new File(service.getInstanceLayout().getPartitionsDirectory(), "system"));
        systemPartition.setSchemaManager(service.getSchemaManager());

        factory.addIndex(systemPartition, SchemaConstants.OBJECT_CLASS_AT, 100);

        service.setSystemPartition(systemPartition);
    }

    /**
     * Add a new partition to the server
     *
     * @param partitionId The partition Id
     * @param partitionDn The partition DN
     * @return The newly added partition
     * @throws Exception If the partition can't be added
     */
    private Partition addPartition(String partitionId, String partitionDn) throws Exception {
        // Create a new partition named 'foo'.
        Partition partition =
                factory.createPartition(service.getSchemaManager(), service.getDnFactory(), partitionId, partitionDn,
                        100, service.getInstanceLayout().getPartitionsDirectory());
        service.addPartition(partition);
        return partition;
    }


    /**
     * Add a new set of index on the given attributes
     *
     * @param partition The partition on which we want to add index
     * @param attrs     The list of attributes to index
     */
    private void addIndex(Partition partition, String... attrs) throws Exception {
        for (String attribute : attrs) {
            factory.addIndex(partition, attribute, 100);
        }
    }
}
