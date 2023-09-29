class User < ApplicationRecord
  has_many :categories, dependent: :destroy
  has_many :transactions, dependent: :destroy
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
         #:lockable, :timeoutable, :trackable
    

    validates :name, presence: true
end
