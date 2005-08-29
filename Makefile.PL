use ExtUtils::MakeMaker;

# Set version here, so we can change it when either DNS.pm
# or DNSserver.pm change.

$VERSION  = "1.2.0";

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'           => 'Stanford::DNSserver',
    'VERSION'        => $VERSION,
    'dist'           => {
                          COMPRESS     => 'gzip ',
                          SUFFIX       => '.gz',
                          DIST_DEFAULT => 'all tardist'
                        },
    'PREREQ_PM'      => {}, # e.g., Module::Name => 1.1
    'PM'             => {
                          'DNS.pm'       => '$(INST_LIBDIR)/DNS.pm',
                          'DNSserver.pm' => '$(INST_LIBDIR)/DNSserver.pm'
                        },
#   'ABSTRACT_FROM'  => 'DNSserver.pm'
);


