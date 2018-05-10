use std::borrow::Borrow;
use std::collections::{HashMap, LinkedList};
use std::hash::Hash;

pub struct LriHashMap<K, V> {
    capacity: usize,
    hash_map: HashMap<K, V>,
    keys_ordered_by_insertion_time: LinkedList<K>,
}

// Least recently inserted map: this is a data structure that acts as a hash map with a limited
// number of entries. If the map is already full when a (key, value) pair is inserted, then the
// oldest entry is removed, to make room for the new one.
impl<K, V> LriHashMap<K, V>
where
    K: Eq + Hash + Clone,
{
    // todo: should we add a check for capacity > 0 somewhere?
    pub fn new(capacity: usize) -> Self {
        LriHashMap {
            capacity,
            hash_map: HashMap::with_capacity(capacity),
            keys_ordered_by_insertion_time: LinkedList::new(),
        }
    }

    // This should only be called when the LriHashMap is full.
    fn make_room_for_new_key(&mut self) {
        // Being full should imply list len > 0. Otherwise, something is very wrong and unwrap()
        // should panic.
        let old_key = self.keys_ordered_by_insertion_time.pop_back().unwrap();
        // If old_key was in the list, it should also be in the map, therefore unwrap() is safe.
        self.hash_map.remove(&old_key).unwrap();
    }

    // Helper method called by the public insert functions.
    fn do_insert(&mut self, k: K, v: V, key_already_present: bool) -> Option<V> {
        // An alternative to cloning the key is to use an Rc, but we'll think about the
        // trade-offs at some point in the future.
        if !key_already_present {
            self.keys_ordered_by_insertion_time.push_front(k.clone());
        }
        self.hash_map.insert(k, v)
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let key_already_present = self.contains_key(&k);
        if self.keys_ordered_by_insertion_time.len() == self.capacity && !key_already_present {
            self.make_room_for_new_key();
        }

        self.do_insert(k, v, key_already_present)
    }

    pub fn insert_unique(&mut self, k: K, v: V) -> Result<(), V> {
        if self.hash_map.contains_key(&k) {
            return Err(v);
        }

        if self.keys_ordered_by_insertion_time.len() == self.capacity {
            self.make_room_for_new_key();
        }

        // We made sure at the beginning that the key is not in the map already.
        self.do_insert(k, v, false);
        Ok(())
    }

    // The inspiration for the signature of the "get*" functions came from the declaration
    // of HashMap::get().
    pub fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash,
    {
        self.hash_map.get(k)
    }

    pub fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash,
    {
        self.hash_map.get_mut(k)
    }

    pub fn contains_key<Q: ?Sized>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash,
    {
        self.hash_map.contains_key(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map() {
        let mut m = LriHashMap::<u32, u32>::new(3);

        assert!(!m.contains_key(&1));
        m.insert(1, 1);
        assert!(m.contains_key(&1));

        assert!(m.insert(2, 2).is_none());
        assert!(m.insert(3, 3).is_none());

        assert_eq!(m.insert(3, 4), Some(3));
        assert_eq!(m.get(&3), Some(&4));
        assert_eq!(m.get(&100), None);

        *m.get_mut(&3).unwrap() = 5;
        assert_eq!(m.get(&3), Some(&5));

        assert!(m.contains_key(&1));
        assert!(!m.contains_key(&100));

        assert_eq!(m.insert_unique(3, 6), Err(6));
        // Let's make sure the old value has not been overwritten.
        assert_eq!(m.get(&3), Some(&5));

        // The map should be full right now. The oldest element must be removed
        // on the next insertion.
        assert_eq!(m.hash_map.len(), 3);
        assert_eq!(m.keys_ordered_by_insertion_time.len(), 3);

        assert_eq!(m.insert_unique(4, 4), Ok(()));
        assert!(!m.contains_key(&1));
    }
}
