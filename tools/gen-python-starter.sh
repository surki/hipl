#!/bin/sh

# This shell script generates another shell script according to its arguments.
# The generated script invokes the python script from the right directory.
# The reason why a script is generated is that "make install" and
# "dpkg -i dnsproxy.deb" (or rpm) store python scripts to different paths
# (/usr/local vs. /usr). Thus, this script adjusts the paths of the generated
# script according to configure.
#
# If you discover a better way to wrap python software with automake and
# deb/rpm binary packages, please make sure that all the four invocation
# methods to the python scripts still work. Here is an example with dnsproxy:
#
# 1. tools/hipdnsproxy
# 2. cd tools && ./hipdnsproxy
# 3. make install && hipdnsproxy
# 4. make deb && dpkg -i hipl-dnsproxy-version.deb && hipdnsproxy
# 5. all the previous use cases with command line arguments to
#    hipdnsproxy - required for deb/rpm packaging

PYTHON_PATH=$1
PYTHON_SCRIPT=$2
SHELL_SCRIPT=$3

cat > $SHELL_SCRIPT <<EOF
#!/bin/sh
path=\`dirname \$0\`
dev_script=tools/$PYTHON_SCRIPT
if test ! -x \$dev_script
then
    dev_script=$PYTHON_SCRIPT
fi

if echo \$path|grep -q /usr
then
  python $PYTHON_PATH/$PYTHON_SCRIPT \$@
else
  python \$dev_script \$@
fi
EOF

chmod a+rx $SHELL_SCRIPT
