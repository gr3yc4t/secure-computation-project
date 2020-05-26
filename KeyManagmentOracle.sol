pragma experimental ABIEncoderV2;

import "verifier.sol";


contract KeyManagement is Verifier{
    
    
    struct Collision{
        uint128 collisionIndex;     //The i-th collision index
        uint256 collisionKey0;       //The c_i_0 value
        uint256 collisionKey1;       //The c_i_1 value
        uint256 collisionSignature; //Hash(m || i)
        uint256 blockNumber;
        bytes32 reason;             //A string that briefly explain the reason for the redactable-blockchain modification
    }
    
    
    struct Commitment{
        uint256 commitment;         //The commitment of the chameleon hash trapdoor key
        
        //Pedersen Commitment parameters
        uint256 g;
        uint256 h;
    }
    
    
    
    Commitment trapdoor;    //Commitment to the trapdoor c0
    uint128 k;              //The number of times a block can be redacted
    
    
    mapping (uint256 => Collision[]) private collision_ledger;      //Ledger that contains all the collision occurred so far
    
    mapping (uint256 => bytes32) private chameleon_randomness;         //Mapping that contains the randomness to "unlock" collisions for the block i
    
    
    
    constructor(uint256 _commitment, uint256 _g, uint256 _h, uint128 _k) public{
        k = _k;
        
        Commitment memory _trapdoor;
        
        _trapdoor.commitment = _commitment;
        _trapdoor.g = _g;
        _trapdoor.h = _h;
        
        trapdoor = _trapdoor;
    }
    
    

    
    //TODO: Add an option where the collider must stake its money to perform a collision
    //TODO: Remove the constraint of 16 variables (cannot provide "reason")
    /**
     * Zokrates Inputs:
     *  - c0          -> _collisionKey1
     *  - c1          -> _collisionKey2
     *  - keyIndex    -> function input "collisionIndex"
     *  - blockNumber -> function input
     *  - commitment  -> present on contract
     *  - G           -> present on contract
     *  - h           -> present on contract
     *  - (private) message
     *  - (private) randomness
     *  - Last input = zookrates return = 1
     */
    
    
    function FinalizeCollision(
        uint256 _blockNumber, uint256 _collisionKey1, uint256 _collisionKey2, uint128 _collisionIndex, uint256 _collisionSignature, 
        uint[2] memory _a, uint[2][2] memory _b, uint[2] memory _c
    ) public returns (bool){
        
        require(isBlockCollisionUnlocked(_blockNumber), "Block not unlocked");        
        
        
        //Start checks
        Collision memory last_collision;
        bool collisionExists;
        
        
        (collisionExists, last_collision) = this.getLastCollision(_blockNumber);
        
        if (collisionExists){
            require(_collisionIndex == last_collision.collisionIndex + 1);  //Ensure that the new collision is performed with the next collision key
        }else{
            require(_collisionIndex == k-2);
        }
        
        
        
        
        uint[8] memory proof_input;
        
        proof_input[0] = _collisionKey1;
        proof_input[1] = _collisionKey2;
        proof_input[2] = _collisionIndex;
        proof_input[3] = _blockNumber;
        proof_input[4] = trapdoor.commitment;
        proof_input[5] = trapdoor.g;
        proof_input[6] = trapdoor.h;
        proof_input[7] = 1;                 //Return value of Zokrates

        
        //Check Proof
        bool proof_result = verifyTx(_a, _b, _c, proof_input);
        
        
        require(proof_result, "Proof not valid");
        
        
        
        Collision memory new_collision;
        
        new_collision.collisionIndex = _collisionIndex;
        new_collision.collisionKey0 = _collisionKey1;
        new_collision.collisionKey1 = _collisionKey2;
        new_collision.collisionSignature = _collisionSignature;
        new_collision.blockNumber = _blockNumber;
        new_collision.reason = "";
    
    
        collision_ledger[_blockNumber].push(new_collision);
    
        return true;
    }
    
    
    
    
    
    
    
    function unlockBlockCollisions(uint256 _blockNumber, bytes32 _randomness) public returns (bool){
        
        require(!isBlockCollisionUnlocked(_blockNumber), "Block already unlocked");
    
        chameleon_randomness[_blockNumber] = _randomness;
        
        return true;
    }
    
    // ---------------------------------------------------------------------------------------------------------
    //                                              GET METHODS
    // ---------------------------------------------------------------------------------------------------------
    
    
    
    
    
    function getCommitment() external view returns(uint256, uint256, uint256){
        return (trapdoor.commitment, trapdoor.g, trapdoor.h);
    }
    
    
    
    
    function getChameleonRandomness(uint256 _blockNumber) external view returns (bytes32){
        return chameleon_randomness[_blockNumber];
    }
    
    
    function isBlockCollisionUnlocked(uint256 _blockNumber) public view returns (bool){
        bytes32 rand = chameleon_randomness[_blockNumber];
        
        if (rand == 0){
            return false;
        }
        
        return true;
    }
    
    
    
    function getLastCollision(uint256 _blockNumber) external view returns (bool, Collision memory){

        require(isBlockCollisionUnlocked(_blockNumber), "Block not unlocked");
    
        
        Collision[] memory blockCollisions = collision_ledger[_blockNumber];
        
        uint len = blockCollisions.length;
        
        
        if (len > 0){
            return (true, blockCollisions[len-1]);  //Return last collision
        }else{
            
            Collision memory empty;
            
            empty.collisionIndex = k+1;     //To make it invalid
            empty.blockNumber = 0;
            
            return (false, empty);
        }
    }
    
    
    
    /// Check if a collision signature ( H( m || i) ) is valid
    /// @param _blockNumber The block to check
    /// @param _data        The collision signature to check
    /// @dev Search _data in the block's collisions mapping
    
    function isValid(uint256 _blockNumber, uint256 _data) external view returns (bool){
        
        Collision[] memory collisions = collision_ledger[_blockNumber];
        
        uint collision_number = collisions.length;
        
        
        for (uint i=0; i<collision_number; i++){
            
            if( collisions[i].collisionSignature == _data ){
                return true;
            }
            
        }
        
        return false;
    }
   
    
    
}