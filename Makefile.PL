use 5.006;
use ExtUtils::MakeMaker;
use strict;
use warnings;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Router::R3',
    VERSION_FROM      => 'lib/Router/R3.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Router/R3.pm', # retrieve abstract from module
       AUTHOR         => 'Cindy Wang (CindyLinz) <cindy@cpan.org>') : ()),
    CONFIGURE_REQUIRES => { 
        'ExtUtils::PkgConfig' => 0,
        'ExtUtils::MakeMaker' => 0,
    },
    CONFIGURE => sub {
        my @CCFLAGS = qw(-O2 -std=c99);
        my @LIBS = qw();
        if( exists &ExtUtils::PkgConfig::find ) {
            my %pkg_info = ExtUtils::PkgConfig->find('libpcre');
            die "libpcre is required." unless %pkg_info;
            print "Found libpcre:\n";
            print "modversion:  $pkg_info{modversion}\n";
            print "cflags:      $pkg_info{cflags}\n";
            print "libs:        $pkg_info{libs}\n";
            push @LIBS, $pkg_info{libs};
        } else {
            push @LIBS, '-lpcre';
        }

        my @INCLUDE_DIRS=qw(.);
        push @INCLUDE_DIRS, "/usr/local/include" if -e "/usr/local/include"; # check for homebrew path
        push @INCLUDE_DIRS, "/opt/local/include" if -e "/opt/local/include"; # check for macports path

        return {
            DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
            LIBS    => \@LIBS,
            CCFLAGS => join(' ',@CCFLAGS),
            INC     => join(' ', map { "-I$_" } @INCLUDE_DIRS),
        };
    },
    # Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
    # CCFLAGS           => join(' ', @CCFLAGS),
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw());
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'Router::R3',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
