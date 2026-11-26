#! /bin/bash

FREE_RAN1_NAMESPACE="free-ran1-ns"
FREE_RAN2_NAMESPACE="free-ran2-ns"
FREE_UE_NAMESPACE="free-ue-ns"

usage() {
    echo "Usage: $0 [ up | down | ran1-ns | ran2-ns | ue-ns ]"
    echo "  up     - Setup RAN1, RAN2 and UE namespaces"
    echo "  down   - Cleanup all namespaces"
    echo "  ran1-ns - Enter RAN1 namespace"
    echo "  ran2-ns - Enter RAN2 namespace"
    echo "  ue-ns  - Enter UE namespace"
    exit 1
}

setup_network_namespace() {
    # Remove exist network namespace
    echo "Removing exist network namespace..."
    cleanup_network_namespace
    echo

    # Create network namespace
    echo "Creating network namespace..."
    sudo ip netns add $FREE_RAN1_NAMESPACE 2>/dev/null || true
    sudo ip netns add $FREE_RAN2_NAMESPACE 2>/dev/null || true
    sudo ip netns add $FREE_UE_NAMESPACE 2>/dev/null || true
    echo

    # Create veth pair
    echo "Creating veth pair and bridge..."
    # Create bridge for connecting RAN1 and RAN2 to same host interface
    sudo ip link add brHo type bridge
    sudo ip link add br-ran1 type veth peer fnsRan1
    sudo ip link add br-ran2 type veth peer fnsRan2
    sudo ip link add fnsGnb1 type veth peer fnsUe1
    sudo ip link add fnsGnb2 type veth peer fnsUe2
    
    # Connect veth pairs to bridge
    sudo ip link set br-ran1 master brHo
    sudo ip link set br-ran2 master brHo
    echo

    # Move veth pair to network namespace
    echo "Moving veth pair to network namespace..."
    sudo ip link set fnsRan1 netns $FREE_RAN1_NAMESPACE
    sudo ip link set fnsRan2 netns $FREE_RAN2_NAMESPACE
    sudo ip link set fnsGnb1 netns $FREE_RAN1_NAMESPACE
    sudo ip link set fnsGnb2 netns $FREE_RAN2_NAMESPACE
    sudo ip link set fnsUe1 netns $FREE_UE_NAMESPACE
    sudo ip link set fnsUe2 netns $FREE_UE_NAMESPACE
    echo

    # Bring up the interface in host namespace
    echo "Bring up the interface in host namespace..."
    sudo ip link set brHo up
    sudo ip link set br-ran1 up
    sudo ip link set br-ran2 up
    echo

    # Bring up the interface in free-ran-ue namespace
    echo "Bring up the interface in free-ran-ue namespace..."
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip link set fnsRan1 up
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip link set fnsRan2 up
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip link set fnsGnb1 up
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip link set fnsGnb2 up
    echo

    # Bring up the interface in free-ran-ue namespace
    echo "Bring up the interface in free-ran-ue namespace..."
    sudo ip netns exec $FREE_UE_NAMESPACE ip link set fnsUe1 up
    sudo ip netns exec $FREE_UE_NAMESPACE ip link set fnsUe2 up
    echo

    # Set up IP address
    echo "Setting up IP address..."
    # free-ran-ue namespace: 10.0.1.0/24 network
    sudo ip addr add 10.0.1.1/24 dev brHo
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip addr add 10.0.1.2/24 dev fnsRan1
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip addr add 10.0.1.3/24 dev fnsRan2
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip addr add 10.0.2.1/24 dev fnsGnb1
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip addr add 10.0.3.1/24 dev fnsGnb2
    sudo ip netns exec $FREE_UE_NAMESPACE ip addr add 10.0.2.2/24 dev fnsUe1
    sudo ip netns exec $FREE_UE_NAMESPACE ip addr add 10.0.3.2/24 dev fnsUe2
    echo

    # Set up default route
    echo "Setting up default route..."
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip route add default via 10.0.1.1
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip route add default via 10.0.1.1
    sudo ip netns exec $FREE_RAN1_NAMESPACE ip route add 10.0.2.0/24 dev fnsGnb1
    sudo ip netns exec $FREE_RAN2_NAMESPACE ip route add 10.0.3.0/24 dev fnsGnb2
    sudo ip netns exec $FREE_UE_NAMESPACE ip route add default via 10.0.2.1
    sudo ip netns exec $FREE_UE_NAMESPACE ip route add 10.0.3.0/24 dev fnsUe2
    echo

    echo "$FREE_RAN1_NAMESPACE namespace setup complete"
    echo "$FREE_RAN2_NAMESPACE namespace setup complete"
    echo "$FREE_UE_NAMESPACE namespace setup complete"
    echo "Network topology:"
    echo "  Host brHo (10.0.1.1) <---> RAN1 namespace (10.0.1.2 | 10.0.2.1) <---> UE namespace (10.0.2.2)"
    echo "  Host brHo (10.0.1.1) <---> RAN2 namespace (10.0.1.3 | 10.0.3.1) <---> UE namespace (10.0.3.2)"
    echo "  Note: Both RAN1 and RAN2 connect to Host via the same bridge interface (brHo)"
}

cleanup_network_namespace() {
    echo "Removing network namespace..."

    # Bring down interface
    sudo ip link set brHo down 2>/dev/null || true
    sudo ip link set br-ran1 down 2>/dev/null || true
    sudo ip link set br-ran2 down 2>/dev/null || true

    # Delete veth pair (deleting one end automatically deletes the pair)
    sudo ip link delete br-ran1 2>/dev/null || true
    sudo ip link delete br-ran2 2>/dev/null || true
    sudo ip link delete fnsGnb1 2>/dev/null || true
    sudo ip link delete fnsGnb2 2>/dev/null || true
    
    # Delete bridge
    sudo ip link delete brHo 2>/dev/null || true

    # Delete network namespace
    sudo ip netns delete $FREE_RAN1_NAMESPACE 2>/dev/null || true
    sudo ip netns delete $FREE_RAN2_NAMESPACE 2>/dev/null || true
    sudo ip netns delete $FREE_UE_NAMESPACE 2>/dev/null || true

    echo "$FREE_RAN1_NAMESPACE namespace removed"
    echo "$FREE_RAN2_NAMESPACE namespace removed"
    echo "$FREE_UE_NAMESPACE namespace removed"
}

main() {
    if [ $# -ne 1 ]; then
        usage
    fi

    case "$1" in
        "up")
            setup_network_namespace
        ;;
        "down")
            cleanup_network_namespace
        ;;
        "ran1-ns")
            sudo ip netns exec $FREE_RAN1_NAMESPACE bash
        ;;
        "ran2-ns")
            sudo ip netns exec $FREE_RAN2_NAMESPACE bash
        ;;
        "ue-ns")
            sudo ip netns exec $FREE_UE_NAMESPACE bash
        ;;
        *)
            usage
        ;;
    esac
}

main "$@"