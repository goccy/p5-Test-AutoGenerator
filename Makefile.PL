use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'AutoTest',
    VERSION_FROM      => 'lib/AutoTest.pm', # finds $VERSION
    PREREQ_PM         => {},
    LICENSE           => 'perl',
    OBJECT            => join(" ", map {$_.'$(OBJ_EXT)'} qw(AutoTest serializer hash util)),
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/AutoTest.pm', # retrieve abstract from module
       AUTHOR         => 'Masaaki Goshima <goccy54@gmail.com>',
      ) : ()),
    ($ExtUtils::MakeMaker::VERSION gt '6.46' ?
    ('META_MERGE'  => {resources => {
                        license     => 'http://dev.perl.org/licenses/',
                        repository  => 'https://github.com/goccy/AutoTest',
                       },
                      }) : ()),
    INC               => '-I.',
);
