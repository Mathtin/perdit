Pushd SocSecExc\src
make clean
make -f RMakefile clean
popd
Pushd Client\src
make clean
make -f RMakefile clean
popd
Pushd Server\src
make clean
make -f RMakefile clean
popd
