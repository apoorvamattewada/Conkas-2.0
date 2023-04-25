pragma solidity ^0.4.25;

contract SimpleToken {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() public {
        owner = msg.sender;
        balances[owner] = 1000000 * 1 ether;
    }

    function transfer(address _to, uint256 _value) public {
        require(balances[msg.sender] >= _value * 1 ether);
        balances[msg.sender] -= _value * 1 ether;
        balances[_to] += _value * 1 ether;
    }

    function() external payable {}
}
