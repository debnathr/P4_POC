# to add veth pair in the system

sudo ip link add name v1.3.1 type veth peer name v1.3.0
sudo ip link add name v1.1.0 type veth peer name v1.1.1


# to set the link up
sudo ip link set dev v1.3.1 up
sudo ip link set dev v1.3.0 up



# set the mtu of the links
sudo ip link set v1.3.1 mtu 9500
sudo ip link set v1.3.0 mtu 9500


# adding bridges
# create a bridge named bridge1, that have v1.2.1  and v3.1.1 as members

sudo ip link add name bridge1 type bridge
sudo ip link set dev bridge1 up
sudo ip link set dev v1.2.1 master bridge1
sudo ip link set dev v3.1.1 master bridge1

sudo ip link add name bridge2 type bridge
sudo ip link set dev bridge2 up
sudo ip link set dev v3.2.1 master bridge1
sudo ip link set dev v2.2.1 master bridge1

sudo ip link add name bridge3 type bridge
sudo ip link set dev bridge3 up
sudo ip link set dev v1.1.1 master bridge1
sudo ip link set dev v2.1.1 master bridge1

# add the ip address to the link v1.3.1 and v3.3.1
ip addr add 10.35.26.01 dev v1.3.1
ip addr add 10.35.26.02 dev v3.3.1


