;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are testing use-fixtures] :as t]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; As a warmup, let's start with some contrived data and demonstrate how
;; authorization works in Site.

;; In Site's authorization system, a subject might cause an effect on a resource
;; (which would change it in some way). The authorization system must first
;; check that the subject (user) is allowed to cause a given effect on the
;; resource.

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/effects/resources.

(defn check-acls
  [db subject effect resource rules]
  (xt/q
   db
   {:find '[acl]
    :where
    '[
      [acl ::site/type "ACL"]
      [effect ::site/type "Effect"]
      [acl ::pass/effect effect]
      (allowed? acl subject effect resource)]

    :rules rules

    :in '[subject effect resource]}

   subject effect resource))

(defn allowed-resources
  [db subject effects rules]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [acl ::site/type "ACL"]
      [effect ::site/type "Effect"]
      [acl ::pass/effect effect]

      [(contains? effects effect)]

      (allowed? acl subject effect resource)]

    :rules rules

    :in '[subject effects]}

   subject effects))

(def ALICE
  {:xt/id "https://example.org/people/alice",
   ::site/type "User"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob",
   ::site/type "User"
   ::username "bob"})

(def CARL
  {:xt/id "https://example.org/people/carl",
   ::site/type "User"
   ::username "carl"})

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"
   ::site/type "Resource"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"
   ::site/type "Resource"})

(def READ_USER_DIR_EFFECT
  {:xt/id "https://example.org/effects/read-user-dir"
   ::site/type "Effect"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"})

(def WRITE_USER_DIR_EFFECT
  {:xt/id "https://example.org/effects/write-user-dir"
   ::site/type "Effect"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/effect-args [{}]})

(def READ_SHARED_EFFECT
  {:xt/id "https://example.org/effects/read-shared"
   ::site/type "Effect"})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/acls/alice-can-read"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/alice"
   ::pass/effect #{"https://example.org/effects/read-shared"
                   "https://example.org/effects/read-user-dir"}})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/acls/alice-can-write-user-dir-content"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/alice"
   ::pass/effect #{"https://example.org/effects/write-user-dir"}})

(def BOB_CAN_READ
  {:xt/id "https://example.org/acls/bob-can-read"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/bob"
   ::pass/effect #{"https://example.org/effects/read-shared"
                   "https://example.org/effects/read-user-dir"}})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/acls/alice-shares-file-with-bob"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/bob"
   ::pass/effect "https://example.org/effects/read-shared"
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/acls/bob-can-write-user-dir-content"
   ::site/type "ACL"
   ::pass/subject "https://example.org/people/bob"
   ::pass/effect #{"https://example.org/effects/write-user-dir"}})

(def WRITE_USER_DIR_RULES
  '[[(allowed? acl subject effect resource)
     [acl ::pass/subject subject]
     [effect :xt/id "https://example.org/effects/write-user-dir"]
     [effect ::pass/resource-matches resource-regex]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_USER_DIR_RULES
  '[[(allowed? acl subject effect resource)
     [acl ::pass/subject subject]
     [effect :xt/id "https://example.org/effects/read-user-dir"]
     [effect ::pass/resource-matches resource-regex]
     [subject ::username username]
     [resource ::site/type "Resource"]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_SHARED_RULES
  '[[(allowed? acl subject effect resource)
     [acl ::pass/subject subject]
     [effect :xt/id "https://example.org/effects/read-shared"]
     [acl ::pass/resource resource]]])

;; TODO: Rename ACL to permission ?
;; TODO: Rename effect to action ?

(deftest user-dir-test
  (submit-and-await!
   [
    [::xt/put ALICE]
    [::xt/put BOB]
    [::xt/put CARL]
    [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
    [::xt/put ALICE_USER_DIR_SHARED_FILE]
    [::xt/put READ_USER_DIR_EFFECT]
    [::xt/put READ_SHARED_EFFECT]
    [::xt/put WRITE_USER_DIR_EFFECT]

    [::xt/put ALICE_CAN_READ]
    [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put ALICES_SHARES_FILE_WITH_BOB]
    [::xt/put BOB_CAN_READ]
    [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]])

  (let [rules (vec (concat WRITE_USER_DIR_RULES READ_USER_DIR_RULES READ_SHARED_RULES))
        db (xt/db *xt-node*)]

    (are [subject effect resource ok?]
        (let [actual (check-acls db subject effect resource rules)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
      "https://example.org/people/alice"
      "https://example.org/effects/read-user-dir"
      "https://example.org/~alice/private.txt"
      true

      ;; Alice can read the file in her user directory which she has shared with
      ;; Bob.
      "https://example.org/people/alice"
      "https://example.org/effects/read-user-dir"
      "https://example.org/~alice/shared.txt"
      true

      ;; Bob cannot read Alice's private file.
      "https://example.org/people/bob"
      "https://example.org/effects/read-user-dir"
      "https://example.org/~alice/private.txt"
      false

      ;; Bob can read the file Alice has shared with him.
      "https://example.org/people/bob"
      "https://example.org/effects/read-shared"
      "https://example.org/~alice/shared.txt"
      true

      ;; Alice can put a file to her user directory
      "https://example.org/people/alice"
      "https://example.org/effects/write-user-dir"
      "https://example.org/~alice/foo.txt"
      true

      ;; Alice can't put a file to Bob's user directory
      "https://example.org/people/alice"
      "https://example.org/effects/write-user-dir"
      "https://example.org/~bob/foo.txt"
      false

      ;; Alice can't put a file outside her user directory
      "https://example.org/people/alice"
      "https://example.org/effects/write-user-dir"
      "https://example.org/index.html"
      false

      ;; Bob can put a file to his user directory
      "https://example.org/people/bob"
      "https://example.org/effects/write-user-dir"
      "https://example.org/~bob/foo.txt"
      true

      ;; Bob can't put a file to Alice's directory
      "https://example.org/people/bob"
      "https://example.org/effects/write-user-dir"
      "https://example.org/~alice/foo.txt"
      false

      ;; Carl cannot put a file to his user directory, as he hasn't been
      ;; granted the write-user-dir effect.
      "https://example.org/people/carl"
      "https://example.org/effects/write-user-dir"
      "https://example.org/~carl/foo.txt"
      false)

    (is (= #{["https://example.org/~alice/shared.txt"]
             ["https://example.org/~alice/private.txt"]}
           (allowed-resources
            db
            "https://example.org/people/alice"
            #{"https://example.org/effects/read-user-dir"
              "https://example.org/effects/read-shared"}
            (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES)))))

    (is (= #{["https://example.org/~alice/shared.txt"]}
           (allowed-resources
            db
            "https://example.org/people/bob"
            #{"https://example.org/effects/read-user-dir"
              "https://example.org/effects/read-shared"}
            (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES)))))))
