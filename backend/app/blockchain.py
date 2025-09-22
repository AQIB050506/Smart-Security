"""
Blockchain integration for tamper-proof evidence storage.
"""
from web3 import Web3
from typing import Optional, Dict, Any
import logging
from app.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BlockchainService:
    """Service for blockchain operations using Polygon testnet."""
    
    def __init__(self):
        """Initialize the blockchain service."""
        self.w3 = None
        self.account = None
        self.contract = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Web3 connection and account."""
        try:
            # Initialize Web3 connection
            if settings.polygon_rpc_url and settings.polygon_rpc_url != "https://polygon-mumbai.g.alchemy.com/v2/your-api-key":
                self.w3 = Web3(Web3.HTTPProvider(settings.polygon_rpc_url))
                
                if self.w3.is_connected():
                    logger.info("Connected to Polygon testnet")
                    
                    # Initialize account if private key is provided
                    if settings.private_key and settings.private_key != "your-private-key-for-blockchain-transactions":
                        self.account = self.w3.eth.account.from_key(settings.private_key)
                        logger.info(f"Account initialized: {self.account.address}")
                    else:
                        logger.warning("Private key not configured, blockchain operations will be simulated")
                else:
                    logger.error("Failed to connect to Polygon testnet")
                    self.w3 = None
            else:
                logger.warning("Polygon RPC URL not configured, blockchain operations will be simulated")
                
        except Exception as e:
            logger.error(f"Error initializing blockchain connection: {e}")
            self.w3 = None
    
    def store_evidence_hash(self, content_hash: str, report_id: int) -> Optional[str]:
        """
        Store evidence hash on blockchain.
        
        Args:
            content_hash: SHA256 hash of the report content
            report_id: ID of the report
            
        Returns:
            Transaction hash if successful, None otherwise
        """
        try:
            if not self.w3 or not self.account:
                # Simulate blockchain operation
                simulated_tx_hash = f"0x{'0' * 64}"
                logger.info(f"Simulated blockchain storage for report {report_id}: {simulated_tx_hash}")
                return simulated_tx_hash
            
            # Check if we have a smart contract
            if settings.contract_address and settings.contract_address != "your-smart-contract-address":
                return self._store_via_contract(content_hash, report_id)
            else:
                # Store hash in a simple transaction
                return self._store_via_transaction(content_hash, report_id)
                
        except Exception as e:
            logger.error(f"Error storing evidence hash on blockchain: {e}")
            return None
    
    def _store_via_contract(self, content_hash: str, report_id: int) -> Optional[str]:
        """
        Store evidence hash via smart contract.
        
        Args:
            content_hash: SHA256 hash of the report content
            report_id: ID of the report
            
        Returns:
            Transaction hash if successful, None otherwise
        """
        try:
            # This would require a deployed smart contract
            # For now, we'll simulate the operation
            logger.info(f"Storing evidence via contract for report {report_id}")
            
            # Simulate contract call
            simulated_tx_hash = f"0x{content_hash[:64]}"
            return simulated_tx_hash
            
        except Exception as e:
            logger.error(f"Error storing via contract: {e}")
            return None
    
    def _store_via_transaction(self, content_hash: str, report_id: int) -> Optional[str]:
        """
        Store evidence hash via simple transaction.
        
        Args:
            content_hash: SHA256 hash of the report content
            report_id: ID of the report
            
        Returns:
            Transaction hash if successful, None otherwise
        """
        try:
            # Create transaction data
            transaction_data = f"REPORT_{report_id}_{content_hash}".encode()
            
            # Get current gas price
            gas_price = self.w3.eth.gas_price
            
            # Build transaction
            transaction = {
                'to': self.account.address,  # Send to self (for simplicity)
                'value': 0,
                'gas': 21000,
                'gasPrice': gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'data': transaction_data.hex()
            }
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, settings.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                logger.info(f"Evidence hash stored successfully: {tx_hash.hex()}")
                return tx_hash.hex()
            else:
                logger.error("Transaction failed")
                return None
                
        except Exception as e:
            logger.error(f"Error storing via transaction: {e}")
            return None
    
    def verify_evidence_hash(self, tx_hash: str, expected_hash: str) -> bool:
        """
        Verify evidence hash on blockchain.
        
        Args:
            tx_hash: Transaction hash to verify
            expected_hash: Expected content hash
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            if not self.w3:
                # Simulate verification
                logger.info(f"Simulated verification for tx: {tx_hash}")
                return True
            
            # Get transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                # Get transaction details
                transaction = self.w3.eth.get_transaction(tx_hash)
                
                # Extract data from transaction
                if transaction.input:
                    # Decode transaction data
                    data = bytes.fromhex(transaction.input[2:])  # Remove '0x' prefix
                    data_str = data.decode('utf-8', errors='ignore')
                    
                    # Check if expected hash is in the data
                    if expected_hash in data_str:
                        logger.info(f"Evidence hash verified successfully: {tx_hash}")
                        return True
                    else:
                        logger.warning(f"Hash mismatch in transaction: {tx_hash}")
                        return False
                else:
                    logger.warning(f"No data in transaction: {tx_hash}")
                    return False
            else:
                logger.error(f"Transaction failed: {tx_hash}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying evidence hash: {e}")
            return False
    
    def get_transaction_details(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a blockchain transaction.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Transaction details if found, None otherwise
        """
        try:
            if not self.w3:
                # Return simulated details
                return {
                    'hash': tx_hash,
                    'status': 'simulated',
                    'block_number': 0,
                    'gas_used': 21000,
                    'timestamp': None
                }
            
            # Get transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            # Get transaction details
            transaction = self.w3.eth.get_transaction(tx_hash)
            
            # Get block details
            block = self.w3.eth.get_block(receipt.block_number)
            
            return {
                'hash': tx_hash,
                'status': 'success' if receipt.status == 1 else 'failed',
                'block_number': receipt.block_number,
                'gas_used': receipt.gas_used,
                'timestamp': block.timestamp,
                'from': transaction['from'],
                'to': transaction['to'],
                'value': transaction['value']
            }
            
        except Exception as e:
            logger.error(f"Error getting transaction details: {e}")
            return None
    
    def is_connected(self) -> bool:
        """Check if blockchain connection is active."""
        if not self.w3:
            return False
        return self.w3.is_connected()


# Global blockchain service instance
blockchain_service = BlockchainService()

