/** @file
 *  HIP Queue
 *  
 * @author: Samu Varjonen <samu.varjonen@hiit.fi>
 * @note:   Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>. This is actually a singly linked list. -samu
 */

/******************************************************************************/
/* INCLUDES */
#include "hipqueue.h"
/******************************************************************************/

HIP_HASHTABLE *opendht_queue = NULL;

/** 
 * hip_hash_opendht_queue - Hash callback for LHASH
 * @param item to be hashed
 * @return the hash
 */
unsigned long hip_hash_opendht_queue(const struct hip_queue *item) {
	uint8_t hash[HIP_AH_SHA_LEN];
	hip_build_digest(HIP_DIGEST_SHA1, (void *)item, sizeof(struct hip_queue), hash);
	return *((unsigned long *)hash);
}
/**
 * hip_compare_opendht_queue - Compare callback for LHASH
 * @param item1 first to be compared
 * @param item2 second to be compared
 * @return 0 on equal otherwise non-zero
 */
int hip_compare_opendht_queue(const struct hip_queue *item1, 
			      const struct hip_queue *item2) {
	return (strcmp((char *)item1, (char *)item2));
}

/**
* hip_init_opendht_queue - This function initializes the opedht_queue 
* @return status of the operation 0 on success, -1 on failure
*/
int hip_init_opendht_queue() {
	opendht_queue = hip_ht_init(hip_hash_opendht_queue, hip_compare_opendht_queue);
	if (opendht_queue == NULL) 
		return(-1);
	return(0);
}

/**
* write_fifo_queue - This function writes data to the hip_queue structure
* @param write_data data to be written on the queue node
* @param data_size_in_bytes size of the data sent
* @return status of the operation 0 on success, -1 on failure
*/
int hip_write_to_opendht_queue (void *write_data, int data_size_in_bytes) {
	extern int opendht_queue_count;
	void *temp_data;
	struct hip_queue *new_item = NULL;
	int err = -1;
	
	_HIP_DEBUG("Write, Items in opendht_queue %d on enter\n", opendht_queue_count);
	temp_data = malloc(data_size_in_bytes);
	HIP_IFEL((!temp_data), -1, "Failed to malloc memory for data\n");
	memset(temp_data, 0, sizeof(data_size_in_bytes));
	memcpy (temp_data,write_data, data_size_in_bytes);

	new_item = (struct hip_queue *)malloc(sizeof(struct hip_queue));
	memset(new_item, 0, sizeof(struct hip_queue));
	HIP_IFEL((!new_item), -1, "Failed to malloc memory for queue new item\n");
	new_item->data_len = data_size_in_bytes;
	new_item->data = temp_data;	               
	err = hip_ht_add(opendht_queue, new_item);
	opendht_queue_count = opendht_queue_count + 1;

	/* Debug line do not leave uncommented */
	//hip_debug_print_opendht_queue();
	_HIP_DEBUG("Write, Items in opendht_queue %d on exit\n", opendht_queue_count);
	
out_err:
	return err ;  
}

/**
* read_fifo_queue - This function writes data to the hip_queue structure
* @param read_data stores the data read from queue node
* @return status of the operation 0 on success, -1 on failure
*/
int hip_read_from_opendht_queue (void *read_data)
{
	int i = 0;
	hip_list_t *item, *tmp;
	struct hip_queue *this;
	extern int opendht_queue_count;

    	_HIP_DEBUG("Read, Items in opendht_queue %d on enter\n", opendht_queue_count);
	
	list_for_each_safe(item, tmp, opendht_queue, i) {
		this = list_entry(item);
		if (this == NULL) return(-1);
		memcpy (read_data, this->data, this->data_len);
		_HIP_DEBUG ("Node data read: %s \n", (char*)read_data);
		hip_ht_delete(opendht_queue, this);
		_HIP_DEBUG("Read, Items in opendht_queue %d on exit\n", opendht_queue_count);	
		opendht_queue_count = opendht_queue_count -1;
		// ugly way but I need only one item at a time and this was fast
		if (this->data) free(this->data);
		if (this) free(this);
	        return(0); 
	}
	/* Debug line do not leave uncommented */
	//hip_debug_print_opendht_queue();
	if (this->data) free(this->data);
	if (this) free(this);
	return(0);
}

/** 
 * debug_print_queue - This function prints all the queue members
 *
 @ return void
*/
void hip_debug_print_opendht_queue() {
	int i = 0;
	hip_list_t *item, *tmp;
	struct hip_queue *entry;
	extern int opendht_queue_count;

	HIP_DEBUG("DEBUGGING QUEUE comment out if left uncommented\n");
	HIP_DEBUG("Head count %d\n", opendht_queue_count);
	list_for_each_safe(item, tmp, opendht_queue, i) {
		entry = list_entry(item);
		HIP_DEBUG("Node data_len = %d\n", entry->data_len);
		HIP_DEBUG("Node data= %s\n", entry->data);
	}  
}
