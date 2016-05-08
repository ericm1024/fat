#!/usr/bin/env python
# filesystem tests 

import unittest
import os
import stat
import itertools
import random
import string
import subprocess

def dir_has_entry(entry, directory='.'):
    entries=os.listdir(directory)
    return entry in entries

class FatTest(unittest.TestCase):
    TEST_ROOT=os.path.abspath(os.path.dirname(__file__))
    MNT_DIR_NAME="mnt"
    DISK_NAME="fat.dat"
    MNT_DIR_PATH=TEST_ROOT+'/'+MNT_DIR_NAME
    DISK_PATH=TEST_ROOT+'/'+DISK_NAME

    def rm(self, name):
        try:
            if os.path.isfile(name):
                os.unlink(name)
            else:
                os.rmdir(name)
        except OSError as e:
            pass

    def setUp(self, mount=True):
        # remove the previous backing store if one exists
        self.rm(self.DISK_PATH)

        # unmount any old instance if one exists
        self.unmount()

        # mount the filesystem
        if mount:
            self.mount()

    def tearDown(self):
        self.unmount()
        self.rm(self.MNT_DIR_PATH)
        self.rm(self.DISK_PATH)

    def mount(self):
        # make the mount directory if it doesn't exist
        if not self.MNT_DIR_NAME in os.listdir(self.TEST_ROOT):
            os.mkdir(self.MNT_DIR_PATH)

        ret=subprocess.call("./fat -s "+self.MNT_DIR_PATH, shell=True)
        self.assertEqual(ret, 0)
        os.chdir(self.MNT_DIR_PATH)

    def unmount(self):
        os.chdir(self.TEST_ROOT)
        subprocess.call("fusermount -u "+self.MNT_DIR_PATH, shell=True,
                        stdout=open(os.devnull), stderr=open(os.devnull))

class CreateUnlinkTest(FatTest):
    def create_portion(self, name):
        os.mknod(name)
        stat=os.stat(name)
        self.assertEqual(stat.st_nlink, 1)
        self.assertEqual(stat.st_size, 0)
        self.assertTrue(dir_has_entry(name))

    def unlink_portion(self, name):
        os.unlink(name)
        self.assertFalse(dir_has_entry(name))

    def do_test_many(self, nr):
        names=[str(i) for i in range(nr)]
        for name in names:
            self.create_portion(name)
        random.shuffle(names)
        for i in range(len(names)):
            entries=os.listdir('.')
            for j in range(i, len(names)):
                self.assertTrue(names[j] in entries)
            self.unlink_portion(names[i])

    def test_one(self):
        self.do_test_many(1)

    def test_one_cluster(self):
        self.do_test_many(8)

    def test_many_clusters(self):
        self.do_test_many(1024)

# this test case is abusive
class MkdirRmdirTest(FatTest):
    def create_portion(self, name, d):
        path=os.path.join(d,name)
        os.mkdir(path)
        stat=os.stat(path)
        self.assertEqual(stat.st_nlink, 2)
        self.assertEqual(stat.st_size, 0)
        self.assertTrue(dir_has_entry(name, d))

    def unlink_portion(self, name, d):
        os.rmdir(os.path.join(d,name))
        self.assertFalse(dir_has_entry(name, d))
    
    def do_test_many(self, nr, depth=0, d='.'):
        names=[str(i) for i in range(nr)]
        nlink=os.stat(d).st_nlink
        for name in names:
            self.create_portion(name, d)
        random.shuffle(names)

        if depth > 0:
            for i in range(nr):
                self.do_test_many(nr, depth-1, os.path.join(d,names[i]))

        for i in range(len(names)):
            entries=os.listdir(d)
            for j in range(i, len(names)):
                self.assertTrue(names[j] in entries)
            self.unlink_portion(names[i], d)
        self.assertEqual(nlink, os.stat(d).st_nlink)

    # single dir deep tests
    def test_one(self):
        self.do_test_many(1)

    def test_one_cluster(self):
        self.do_test_many(8)

    def test_many_clusters(self):
        self.do_test_many(1024)

    # deeper directory tree tests
    def test_one_r(self):
        self.do_test_many(1, depth=50)
            
    def test_one_cluster_r(self):
        self.do_test_many(8, depth=3)

    def test_many_clusters_r(self):
        self.do_test_many(32, depth=2)        

def get_rand_data(length):
       return ''.join(random.choice(string.lowercase) for i in range(length))
        
class ReadWriteTest(FatTest):

    def file_size(self, name):
        stat=os.stat(name)
        return stat.st_size
    
    def do_one_test(self, size):
        name='foo'
        data=get_rand_data(size)
        
        # open, write, close
        fd=os.open(name, os.O_WRONLY|os.O_CREAT|os.O_TRUNC)
        self.assertEqual(self.file_size(name), 0)
        os.write(fd,data[:size/2])
        os.write(fd,data[size/2:])
        self.assertEqual(self.file_size(name), size)
        os.close(fd)

        # open, read, truncate, close, unlink
        fd=os.open(name, os.O_RDWR)
        buf=os.read(fd, size/2) # read first half of file
        self.assertEqual(buf, data[:size/2])
        buf=os.read(fd, size-size/2) # read second half of file
        self.assertEqual(buf, data[size/2:])
        os.ftruncate(fd, 0)
        self.assertEqual(self.file_size(name), 0)
        os.close(fd)
        os.unlink(name)
        
    def test_one_cluster(self):
        self.do_one_test(512)

    def test_many_clusters(self):
        self.do_one_test(512*50)

    def test_weird_sizes(self):
        self.do_one_test(0)
        self.do_one_test(1)
        self.do_one_test(513)
        self.do_one_test(12345)

if __name__ == '__main__':
    unittest.main()
