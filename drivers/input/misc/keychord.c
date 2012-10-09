/*
 *  drivers/input/misc/keychord.c
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
*/

#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/keychord.h>
#include <linux/sched.h>

// pz1945
//#define KEYCHORD_DEBUG

#ifdef KEYCHORD_DEBUG
#include <linux/device.h>
#endif

#define KEYCHORD_NAME		"keychord"
#define BUFFER_SIZE			16

MODULE_AUTHOR("Mike Lockwood <lockwood@android.com>");
MODULE_DESCRIPTION("Key chord input driver");
MODULE_SUPPORTED_DEVICE("keychord");
MODULE_LICENSE("GPL");

#define NEXT_KEYCHORD(kc) ((struct input_keychord *) \
		((char *)kc + sizeof(struct input_keychord) + \
		kc->count * sizeof(kc->keycodes[0])))

struct keychord_device {
	struct input_handler	input_handler;
	int			registered;

	/* list of keychords to monitor */
	struct input_keychord	*keychords;
	int			keychord_count;

	/* bitmask of keys contained in our keychords */
	unsigned long keybit[BITS_TO_LONGS(KEY_CNT)];
	/* current state of the keys */
	unsigned long keystate[BITS_TO_LONGS(KEY_CNT)];
	/* number of keys that are currently pressed */
	int key_down;

	/* second input_device_id is needed for null termination */
	struct input_device_id  device_ids[2];

	spinlock_t		lock;
	wait_queue_head_t	waitq;
	unsigned char		head;
	unsigned char		tail;
	__u16			buff[BUFFER_SIZE];
};

static int check_keychord(struct keychord_device *kdev,
		struct input_keychord *keychord)
{
	int i;

#ifdef KEYCHORD_DEBUG
	printk("%s  keychord->count= %d key_down= %d\n", __func__, keychord->count, kdev->key_down);
#endif
	if (keychord->count != kdev->key_down)
		return 0;

	for (i = 0; i < keychord->count; i++) {
		if (!test_bit(keychord->keycodes[i], kdev->keystate)){
#ifdef KEYCHORD_DEBUG
			printk("keychord->keycodes[i] = %d \n", keychord->keycodes[i]);
#endif
			return 0;
		}
	}

	/* we have a match */
	return 1;
}

static void keychord_event(struct input_handle *handle, unsigned int type,
			   unsigned int code, int value)
{
	struct keychord_device *kdev = handle->private;
	struct input_keychord *keychord;
	unsigned long flags;
	int i, got_chord = 0;

#ifdef KEYCHORD_DEBUG
	printk("%s 1 \n", __func__);
#endif

//pz1945: fix not detected when pressed VOL_UP and VOL_DOWN together.
#ifdef CONFIG_PANTECH_PRESTO_BOARD
	if (type != EV_KEY || code >= KEY_MAX || code == BTN_TOUCH )
#else
	if (type != EV_KEY || code >= KEY_MAX )
#endif
		return;

#ifdef KEYCHORD_DEBUG
	printk("%s 2 code= %d  val= %d \n", __func__, code, value);
#endif
	spin_lock_irqsave(&kdev->lock, flags);
	/* do nothing if key state did not change */
	if (!test_bit(code, kdev->keystate) == !value)
		goto done;


#ifdef KEYCHORD_DEBUG
	printk("%s 3 not same  code= %d val= %d \n", __func__, code, value);
#endif
	__change_bit(code, kdev->keystate);
	if (value)
		kdev->key_down++;
	else
		kdev->key_down--;

	/* don't notify on key up */
	if (!value)
		goto done;
	/* ignore this event if it is not one of the keys we are monitoring */
	if (!test_bit(code, kdev->keybit))
		goto done;

	keychord = kdev->keychords;
	if (!keychord)
		goto done;

	/* check to see if the keyboard state matches any keychords */
	for (i = 0; i < kdev->keychord_count; i++) {
		if (check_keychord(kdev, keychord)) {
			kdev->buff[kdev->head] = keychord->id;
			kdev->head = (kdev->head + 1) % BUFFER_SIZE;
			got_chord = 1;

#ifdef KEYCHORD_DEBUG
			printk("%s 3 got_chord \n", __func__);
#endif
			break;
		}
		/* skip to next keychord */
		keychord = NEXT_KEYCHORD(keychord);
	}

done:
	spin_unlock_irqrestore(&kdev->lock, flags);

	if (got_chord)
		wake_up_interruptible(&kdev->waitq);
}

static int keychord_connect(struct input_handler *handler,
					  struct input_dev *dev,
					  const struct input_device_id *id)
{
	int i, ret;
	struct input_handle *handle;
	struct keychord_device *kdev =
		container_of(handler, struct keychord_device, input_handler);

#ifdef KEYCHORD_DEBUG
	printk("%s 1 \n", __func__);
#endif
	/*
	 * ignore this input device if it does not contain any keycodes
	 * that we are monitoring
	 */
	for (i = 0; i < KEY_MAX; i++) {
		if (test_bit(i, kdev->keybit) && test_bit(i, dev->keybit))
			break;
	}
	if (i == KEY_MAX)
		return -ENODEV;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = KEYCHORD_NAME;
	handle->private = kdev;

	ret = input_register_handle(handle);
	if (ret)
		goto err_input_register_handle;

	ret = input_open_device(handle);
	if (ret)
		goto err_input_open_device;

#ifdef KEYCHORD_DEBUG
	printk("keychord: using input dev %s for fevent\n", dev->name);
#endif
	return 0;

err_input_open_device:
	input_unregister_handle(handle);
err_input_register_handle:
	kfree(handle);
	return ret;
}

static void keychord_disconnect(struct input_handle *handle)
{
#ifdef KEYCHORD_DEBUG
	printk("%s 1 \n", __func__);
#endif
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

/*
 * keychord_read is used to read keychord events from the driver
 */
static ssize_t keychord_read(struct file *file, char __user *buffer,
		size_t count, loff_t *ppos)
{
	struct keychord_device *kdev = file->private_data;
	__u16   id;
	int retval;
	unsigned long flags;

	if (count < sizeof(id))
		return -EINVAL;
	count = sizeof(id);

	
#ifdef KEYCHORD_DEBUG
	printk("%s 1 \n", __func__);
#endif

	if (kdev->head == kdev->tail && (file->f_flags & O_NONBLOCK))
		return -EAGAIN;

	retval = wait_event_interruptible(kdev->waitq,
			kdev->head != kdev->tail);
	if (retval)
		return retval;

#ifdef KEYCHORD_DEBUG
	printk("%s 2 \n", __func__);
#endif
	spin_lock_irqsave(&kdev->lock, flags);
	/* pop a keychord ID off the queue */
	id = kdev->buff[kdev->tail];
	kdev->tail = (kdev->tail + 1) % BUFFER_SIZE;
	spin_unlock_irqrestore(&kdev->lock, flags);

#ifdef KEYCHORD_DEBUG
	printk("%s id= %d  3\n", __func__, id);
#endif

	if (copy_to_user(buffer, &id, count))
		return -EFAULT;

	return count;
}

/*
 * keychord_write is used to configure the driver
 */
static ssize_t keychord_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	struct keychord_device *kdev = file->private_data;
	struct input_keychord *keychords = 0;
	struct input_keychord *keychord, *next, *end;
	int ret, i, key;
	unsigned long flags;

#ifdef KEYCHORD_DEBUG
	printk("%s 1\n", __func__);
#endif
	if (count < sizeof(struct input_keychord))
		return -EINVAL;
	keychords = kzalloc(count, GFP_KERNEL);
	if (!keychords)
		return -ENOMEM;

	/* read list of keychords from userspace */
	if (copy_from_user(keychords, buffer, count)) {
		kfree(keychords);
		return -EFAULT;
	}

#ifdef KEYCHORD_DEBUG
	printk("%s 2 \n", __func__);
#endif
	/* unregister handler before changing configuration */
	if (kdev->registered) {
		input_unregister_handler(&kdev->input_handler);
		kdev->registered = 0;
	}

	spin_lock_irqsave(&kdev->lock, flags);
	/* clear any existing configuration */
	kfree(kdev->keychords);
	kdev->keychords = 0;
	kdev->keychord_count = 0;
	kdev->key_down = 0;
	memset(kdev->keybit, 0, sizeof(kdev->keybit));
	memset(kdev->keystate, 0, sizeof(kdev->keystate));
	kdev->head = kdev->tail = 0;

	keychord = keychords;
	end = (struct input_keychord *)((char *)keychord + count);

	while (keychord < end) {
		next = NEXT_KEYCHORD(keychord);
		if (keychord->count <= 0 || next > end) {
			pr_err("keychord: invalid keycode count %d\n",
				keychord->count);
			goto err_unlock_return;
		}
		if (keychord->version != KEYCHORD_VERSION) {
			pr_err("keychord: unsupported version %d\n",
				keychord->version);
			goto err_unlock_return;
		}

		/* keep track of the keys we are monitoring in keybit */
		for (i = 0; i < keychord->count; i++) {
			key = keychord->keycodes[i];
			if (key < 0 || key >= KEY_CNT) {
				pr_err("keychord: keycode %d out of range\n",
					key);
				goto err_unlock_return;
			} else {
#ifdef KEYCHORD_DEBUG
				printk("key %d \n",key);
#endif			
			}
			__set_bit(key, kdev->keybit);
		}

		kdev->keychord_count++;
		keychord = next;
	}

	kdev->keychords = keychords;
	spin_unlock_irqrestore(&kdev->lock, flags);

	ret = input_register_handler(&kdev->input_handler);
	if (ret) {
		kfree(keychords);
		kdev->keychords = 0;
		return ret;
	}
	kdev->registered = 1;

	return count;

err_unlock_return:
	spin_unlock_irqrestore(&kdev->lock, flags);
	kfree(keychords);
	return -EINVAL;
}

static unsigned int keychord_poll(struct file *file, poll_table *wait)
{
	struct keychord_device *kdev = file->private_data;

	poll_wait(file, &kdev->waitq, wait);

	if (kdev->head != kdev->tail) {
#ifdef KEYCHORD_DEBUG
		printk(" %s poll occurred \n", __func__);
#endif		
		return POLLIN | POLLRDNORM;

	}
	return 0;
}

static int keychord_open(struct inode *inode, struct file *file)
{
	struct keychord_device *kdev;
	
#ifdef KEYCHORD_DEBUG
	printk("%s 1 \n", __func__);
#endif
	kdev = kzalloc(sizeof(struct keychord_device), GFP_KERNEL);
	if (!kdev)
		return -ENOMEM;

#ifdef KEYCHORD_DEBUG
	printk("%s 2 \n", __func__);
#endif
	spin_lock_init(&kdev->lock);
	init_waitqueue_head(&kdev->waitq);

	kdev->input_handler.event = keychord_event;
	kdev->input_handler.connect = keychord_connect;
	kdev->input_handler.disconnect = keychord_disconnect;
	kdev->input_handler.name = KEYCHORD_NAME;
	kdev->input_handler.id_table = kdev->device_ids;

	kdev->device_ids[0].flags = INPUT_DEVICE_ID_MATCH_EVBIT;
	__set_bit(EV_KEY, kdev->device_ids[0].evbit);

	file->private_data = kdev;

	return 0;
}

static int keychord_release(struct inode *inode, struct file *file)
{
	struct keychord_device *kdev = file->private_data;
	
#ifdef KEYCHORD_DEBUG
	printk("%s \n", __func__);
#endif
	if (kdev->registered)
		input_unregister_handler(&kdev->input_handler);
	kfree(kdev);

	return 0;
}

static const struct file_operations keychord_fops = {
	.owner		= THIS_MODULE,
	.open		= keychord_open,
	.release	= keychord_release,
	.read		= keychord_read,
	.write		= keychord_write,
	.poll		= keychord_poll,
};

static struct miscdevice keychord_misc = {
	.fops		= &keychord_fops,
	.name		= KEYCHORD_NAME,
	.minor		= MISC_DYNAMIC_MINOR,
};

static int __init keychord_init(void)
{
	return misc_register(&keychord_misc);
}

static void __exit keychord_exit(void)
{
	misc_deregister(&keychord_misc);
}

module_init(keychord_init);
module_exit(keychord_exit);
