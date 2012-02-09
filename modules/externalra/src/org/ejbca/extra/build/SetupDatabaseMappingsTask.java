package org.ejbca.extra.build;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;

public class SetupDatabaseMappingsTask extends Task {

    @Override
    public void execute() throws BuildException {
        for (int i = 1; i <= 25; i++) {
            Project project = getProject();
            project.setProperty("number", Integer.toString(i));
            final String source = "externalra.source-" + i;
            final String jdbcUrl = project.getProperty(source + ".jdbc-url");
            final String username = project.getProperty(source + ".username");
            final String password = project.getProperty(source + ".password");
        
            if (jdbcUrl != null && jdbcUrl.length() > 0 &&
                username != null && username.length() > 0 &&
                password != null && password.length() > 0) {
                String driverClass = null;
                String hibernateDialect = null;
                
                // See https://www.hibernate.org/hib_docs/v3/api/org/hibernate/dialect/package-summary.html
                if (jdbcUrl.startsWith("jdbc:mysql:")) {
                    driverClass = "com.mysql.jdbc.Driver";
                    hibernateDialect = "org.hibernate.dialect.MySQL5Dialect";
                } else if (jdbcUrl.startsWith("jdbc:postgresql:")) {
                    driverClass = "org.postgresql.Driver";
                    hibernateDialect = "org.hibernate.dialect.PostgreSQLDialect";
                } else if (jdbcUrl.startsWith("jdbc:hsqldb:")) {
                    driverClass = "org.hsqldb.jdbcDriver";
                    hibernateDialect = "org.hibernate.dialect.HSQLDialect";
                } else {
                    throw new BuildException("Unsupported database with JDBC URL " + jdbcUrl);
                }
                
                project.setProperty("jdbcurl", jdbcUrl);
                project.setProperty("username", username);
                project.setProperty("password", password);
                project.setProperty("driver-class", driverClass);
                project.setProperty("hibernate.dialect", hibernateDialect);
                                
                project.executeTarget("setup-database-mapping-file");
            }
            
        }
        
    }

}